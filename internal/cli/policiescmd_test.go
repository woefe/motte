package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/testutil"
)

// mustDirHash returns the hash of the current directory.
func mustDirHash(t *testing.T) string {
	t.Helper()
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// assertConfigureRejects covers the configure flow's re-validation: a scope
// file that fails to parse after editing exits non-zero without another
// report, since the configure flow already explained the failure.
func assertConfigureRejects(t *testing.T, configure func(scope string) error) {
	t.Helper()
	err := configure("global")
	if err == nil || !errors.Is(err, config.ErrInvalidAfterEdit) {
		t.Errorf("error = %v, want the invalid-after-edit failure", err)
	}
}

// TestPoliciesConfigureCreatesTheTemplate covers the configure command: a
// missing scope file is created from the template and validates afterwards,
// for the global scope, this directory's project scope, and a foreign hash.
func TestPoliciesConfigureCreatesTheTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	for _, scope := range []string{"global", "project", "1234567890ab"} {
		if err := runPoliciesConfigure(scope); err != nil {
			t.Fatalf("runPoliciesConfigure(%s): %v", scope, err)
		}
	}
	files := []string{"global.yaml", mustDirHash(t) + ".yaml", "1234567890ab.yaml"}
	for _, name := range files {
		path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies", name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading the policy file: %v", err)
		}
		if !strings.Contains(string(content), "network:") {
			t.Errorf("%s = %q, want the template", name, string(content))
		}
		entries, err := policies.ReadPolicyFile(path)
		if err != nil {
			t.Fatalf("%s does not validate: %v", name, err)
		}
		if len(entries) != 0 {
			t.Errorf("%s entries = %v, want none", name, entries)
		}
	}
}

// TestPoliciesConfigureRejectsAnInvalidFile covers the validation after the
// editor exits.
func TestPoliciesConfigureRejectsAnInvalidFile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	testutil.WriteConfigFile(t, "policies/global.yaml", "network:\n  alow:\n    - \"extra.example.com\"\n")
	assertConfigureRejects(t, runPoliciesConfigure)
}

// TestPoliciesLsListsGroups covers the grouped listing: only scopes with
// files, blank lines between groups, the current-directory mark, and
// placeholder bodies.
func TestPoliciesLsListsGroups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteConfigFile(t, "policies/global.yaml", testutil.Fixture(t, "policies/ls/global.yaml"))
	testutil.WriteConfigFile(t, "policies/golang.yaml", "network:\n  allow: []\n")
	testutil.WriteConfigFile(t, "policies/"+hash+".yaml", testutil.Fixture(t, "policies/ls/project.yaml"))
	testutil.WriteConfigFile(t, "policies/ffffffffffff.yaml", testutil.Fixture(t, "policies/ls/foreign.yaml"))
	stdout, stderr := testutil.CaptureOutput(t, func() {
		if err := runPoliciesLs(); err != nil {
			t.Errorf("runPoliciesLs: %v", err)
		}
	})
	want := fmt.Sprintf(`global:
  global.example.com
  *.opencode.ai

profile golang:
  (no entries)

project %s (this directory):
  project.example.com

project ffffffffffff:
  other.example.com
`, hash)
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want none", stderr)
	}
}

// TestPoliciesLsEmpty prints the create hint when no policy file exists.
func TestPoliciesLsEmpty(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	stdout, stderr := testutil.CaptureOutput(t, func() {
		if err := runPoliciesLs(); err != nil {
			t.Errorf("runPoliciesLs: %v", err)
		}
	})
	if stdout != "" {
		t.Errorf("stdout = %q, want none", stdout)
	}
	if !strings.Contains(stderr, "no policies configured") {
		t.Errorf("stderr = %q, want the create hint", stderr)
	}
}

// TestPoliciesLsReportsUnreadableScopes shows a scope's parse error under its
// group header.
func TestPoliciesLsReportsUnreadableScopes(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/global.yaml", "network: [oops\n")
	stdout, _ := testutil.CaptureOutput(t, func() {
		if err := runPoliciesLs(); err != nil {
			t.Errorf("runPoliciesLs: %v", err)
		}
	})
	if !strings.HasPrefix(stdout, "global:\n  <unreadable: ") {
		t.Errorf("stdout = %q, want the unreadable group", stdout)
	}
}
