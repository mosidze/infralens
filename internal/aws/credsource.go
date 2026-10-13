package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// Credentials normally come from the SDK. With SSO profiles there is a
// failure mode seen in practice: the AWS CLI keeps working from its own
// credential cache while the SDK tries to refresh the SSO token and gets
// InvalidGrantException. When that happens the tool asks the CLI for the
// credentials it already holds (`aws configure export-credentials`), so
// anything that works in the user's terminal works here too.

// cliRunner runs the aws CLI; replaced in tests.
var cliRunner = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "aws", args...).Output()
}

type processCreds struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// exportCLICredentials asks the CLI for the current credentials of a profile.
func exportCLICredentials(ctx context.Context, profile string) (aws.Credentials, error) {
	args := []string{"configure", "export-credentials", "--format", "process"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	out, err := cliRunner(ctx, args...)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws CLI could not provide credentials for profile %q: %w", profile, err)
	}
	var pc processCreds
	if err := json.Unmarshal(out, &pc); err != nil {
		return aws.Credentials{}, fmt.Errorf("unreadable output of aws configure export-credentials: %w", err)
	}
	if pc.AccessKeyID == "" || pc.SecretAccessKey == "" {
		return aws.Credentials{}, fmt.Errorf("aws CLI returned no credentials for profile %q", profile)
	}
	c := aws.Credentials{
		AccessKeyID: pc.AccessKeyID, SecretAccessKey: pc.SecretAccessKey, SessionToken: pc.SessionToken,
		Source: "aws-cli export-credentials",
	}
	if pc.Expiration != "" {
		if t, err := time.Parse(time.RFC3339, pc.Expiration); err == nil {
			c.CanExpire, c.Expires = true, t
		}
	}
	return c, nil
}

func isSSOFailure(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "SSO") || strings.Contains(m, "InvalidGrant") || strings.Contains(m, "token has expired")
}

// credResolver decides once per profile which provider to use.
type credResolver struct {
	once     sync.Once
	provider aws.CredentialsProvider // nil: use the SDK's own
	note     string
}

// resolve checks the SDK's credentials and, only when they fail for an SSO
// reason, switches to the CLI. The decision is cached.
func (dc *DiscoveryClient) credentials(ctx context.Context) aws.CredentialsProvider {
	dc.cred.once.Do(func() {
		if dc.Profile == "" {
			return
		}
		cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(dc.Profile))
		if err != nil {
			return
		}
		if _, err := cfg.Credentials.Retrieve(ctx); err == nil || !isSSOFailure(err) {
			return
		}
		// the SDK cannot refresh; try the CLI before giving up
		if _, err := exportCLICredentials(ctx, dc.Profile); err != nil {
			return
		}
		prof := dc.Profile
		dc.cred.provider = aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return exportCLICredentials(ctx, prof)
		}))
		dc.cred.note = "using credentials from the aws CLI (the SDK could not refresh the SSO token)"
	})
	return dc.cred.provider
}

// CredentialNote tells the user when the CLI fallback is in use.
func (dc *DiscoveryClient) CredentialNote() string { return dc.cred.note }
