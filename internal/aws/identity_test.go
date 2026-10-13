package aws

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestListProfiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	body := `[default]
region = eu-north-1

[profile client-prod]
sso_session = s

[profile client-stage]
[sso-session my-sso]
sso_start_url = x
[services foo]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", p)
	got, err := ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	// a [default] that does define credentials is kept
	p2 := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p2, []byte("[default]\nsso_session = s\n"), 0o600)
	t.Setenv("AWS_CONFIG_FILE", p2)
	if d, _ := ListProfiles(); !reflect.DeepEqual(d, []string{"default"}) {
		t.Fatalf("default with sso_session must be kept: %v", d)
	}
	t.Setenv("AWS_CONFIG_FILE", p)
	want := []string{"client-prod", "client-stage"} // bare [default] has no credential settings
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
