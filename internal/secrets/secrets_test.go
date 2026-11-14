package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/testutil"
)

// TestValidateName checks the secret env var naming rule.
func TestValidateName(t *testing.T) {
	for _, ok := range []string{"EXAMPLE_API_KEY", "_TOKEN", "key_1"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "1KEY", "golang/EXAMPLE_API_KEY", "FOO-BAR", "a b"} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) = nil, want an error", bad)
		}
	}
}

// TestValidateAllowEntry covers the host-pattern grammar of secret allow
// lists (exact hosts, *.suffix wildcards, and `*`).
func TestValidateAllowEntry(t *testing.T) {
	for _, ok := range []string{"*", "api.example.com", "*.example.com", "a.b.c.d"} {
		if err := ValidateAllowEntry(ok); err != nil {
			t.Errorf("ValidateAllowEntry(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "webserver", "localhost", "*.com", "*.example.com:443", "*. *", "ex ample.com"} {
		if err := ValidateAllowEntry(bad); err == nil {
			t.Errorf("ValidateAllowEntry(%q) = nil, want an error", bad)
		}
	}
}

// TestReadWriteAndRemoveMeta round-trips a secret settings file and covers
// schema strictness: unknown fields fail, allow is required, header fields
// default.
func TestReadWriteAndRemoveMeta(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	const name = "EXAMPLE_API_KEY"
	spec := Spec{Allow: []string{"*.opencode.ai"}, HeaderFields: []string{"authorization"}}
	if err := WriteMeta(name, spec); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	got, err := Read(name)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Name != name || got.EnvVar != name ||
		len(got.Allow) != 1 || got.Allow[0] != "*.opencode.ai" ||
		len(got.HeaderFields) != 1 || got.HeaderFields[0] != "authorization" {
		t.Fatalf("Read = %+v", got)
	}

	// The secret lives in its own file with 0600 permissions and the header
	// comment.
	path, err := Path(name)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "EXAMPLE_API_KEY.yaml" {
		t.Errorf("Path = %q, want EXAMPLE_API_KEY.yaml", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("statting the secret file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("secret file mode = %#o, want 0600", perm)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the secret file: %v", err)
	}
	if !strings.Contains(string(content), "# motte secret — EXAMPLE_API_KEY") ||
		!strings.Contains(string(content), "---\nallow:") ||
		!strings.Contains(string(content), "*.opencode.ai") {
		t.Errorf("secret file = %q, want the header comment, document marker, and hosts", string(content))
	}

	// Header fields default when omitted.
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow:\n  - \"api.example.com\"\n")
	got, err = Read(name)
	if err != nil {
		t.Fatalf("Read(default headers): %v", err)
	}
	if !slices.Equal(got.HeaderFields, DefaultHeaderFields) {
		t.Errorf("HeaderFields = %v, want %v", got.HeaderFields, DefaultHeaderFields)
	}

	// Unknown fields fail lint-style, with the path in the error.
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml",
		"allow: [\"api.example.com\"]\nalow: [oops]\n")
	_, err = Read(name)
	if err == nil || !strings.Contains(err.Error(), "invalid secret config") || !strings.Contains(err.Error(), "alow") {
		t.Errorf("error = %v, want an unknown-field error naming alow", err)
	}

	// A missing allow list is invalid.
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "header_fields: [origin]\n")
	if _, err := Read(name); err == nil || !strings.Contains(err.Error(), "empty allow list") {
		t.Errorf("error = %v, want an empty-allow error", err)
	}

	// Allow hosts must be host patterns, not network rule targets.
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow: [\"host:tcp:9931\"]\n")
	if _, err := Read(name); err == nil || !strings.Contains(err.Error(), "invalid secret allow host") {
		t.Errorf("error = %v, want a bad-host error", err)
	}

	// Removing deletes the file and subsequent Read returns ErrNotFound.
	if err := RemoveMeta(name); err != nil {
		t.Fatalf("RemoveMeta: %v", err)
	}
	if _, err := Read(name); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read after RemoveMeta = %v, want ErrNotFound", err)
	}
}

// TestTemplate covers the secret settings skeleton: it validates out of the
// box.
func TestTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	tmpl, err := Template("EXAMPLE_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tmpl, "# motte secret — EXAMPLE_API_KEY") ||
		!strings.Contains(tmpl, "motte secrets set EXAMPLE_API_KEY") ||
		!strings.Contains(tmpl, "---\nallow:") {
		t.Errorf("Template = %q, want the header comments and document marker", tmpl)
	}
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", tmpl)
	spec, err := Read("EXAMPLE_API_KEY")
	if err != nil {
		t.Fatalf("Read(template): %v", err)
	}
	if len(spec.Allow) != 1 || spec.Allow[0] != "api.example.com" {
		t.Errorf("template spec = %+v", spec)
	}
}
