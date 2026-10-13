package aws

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AccountID returns the account the profile's credentials belong to.
func (dc *DiscoveryClient) AccountID(ctx context.Context) (string, error) {
	cfg, err := dc.loadConfig(ctx, "us-east-1")
	if err != nil {
		return "", err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

var profileHeader = regexp.MustCompile(`^\[\s*(?:profile\s+)?([^\]\s]+)\s*\]`)

// credentialKeys mark a config section as one that can actually obtain
// credentials. A bare [default] with only region/output does not, and
// probing it would hang on the EC2 metadata service.
var credentialKeys = map[string]bool{
	"sso_session": true, "sso_start_url": true, "role_arn": true, "source_profile": true,
	"credential_process": true, "web_identity_token_file": true, "aws_access_key_id": true,
}

// ListProfiles returns the profile names from the shared AWS config file
// (AWS_CONFIG_FILE or ~/.aws/config). sso-session and other non-profile
// sections are skipped, as is a [default] that has no credential settings.
func ListProfiles() ([]string, error) {
	path := os.Getenv("AWS_CONFIG_FILE")
	if path == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(h, ".aws", "config")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	cur, curOK := "", false
	flush := func() {
		if cur != "" && (cur != "default" || curOK) {
			out = append(out, cur)
		}
		cur, curOK = "", false
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			flush()
			if strings.HasPrefix(line, "[sso-session") || strings.HasPrefix(line, "[services") {
				continue
			}
			if m := profileHeader.FindStringSubmatch(line); m != nil {
				cur = m[1]
			}
			continue
		}
		if cur != "" {
			if k, _, ok := strings.Cut(line, "="); ok && credentialKeys[strings.TrimSpace(k)] {
				curOK = true
			}
		}
	}
	flush()
	sort.Strings(out)
	return out, sc.Err()
}
