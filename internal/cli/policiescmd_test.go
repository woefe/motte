package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/testutil"
)

// assertConfigureRejects covers the configure flow's re-validation: a file
// that fails to parse after editing exits non-zero without another report,
// since the configure flow already explained the failure.
func assertConfigureRejects(t *testing.T, configure func(errOut io.Writer, name string) error, name string) {
	t.Helper()
	err := configure(io.Discard, name)
	if err == nil || !errors.Is(err, config.ErrInvalidAfterEdit) {
		t.Errorf("error = %v, want the invalid-after-edit failure", err)
	}
}

// TestPoliciesConfigureCreatesTheTemplate covers the configure command: a
// missing group file is created from the template and validates afterwards.
func TestPoliciesConfigureCreatesTheTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	if err := runPoliciesConfigure(io.Discard, "work-vpn"); err != nil {
		t.Fatalf("runPoliciesConfigure(work-vpn): %v", err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies", "work-vpn.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the policy group file: %v", err)
	}
	if !strings.Contains(string(content), "# motte policy group — work-vpn") ||
		!strings.Contains(string(content), "allow:") {
		t.Errorf("work-vpn.yaml = %q, want the template", string(content))
	}
	entries, err := policies.ReadGroupFile(path)
	if err != nil {
		t.Fatalf("work-vpn.yaml does not validate: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("work-vpn.yaml entries = %v, want none", entries)
	}
}

// TestPoliciesConfigureRejectsAnInvalidFile covers the validation after the
// editor exits.
func TestPoliciesConfigureRejectsAnInvalidFile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", "alow:\n  - \"extra.example.com\"\n")
	assertConfigureRejects(t, runPoliciesConfigure, "work-vpn")
}

// TestPoliciesLsListsGroupsAndEffectivePolicy covers the listing of user
// policy groups and the current project's effective network policy.
func TestPoliciesLsListsGroupsAndEffectivePolicy(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteConfigFile(t, "policies/empty-group.yaml", "allow: []\n")
	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", "allow:\n  - \"*.corp.example.com\"\n")
	if _, err := project.WriteCurrent(project.Config{
		Image:       "ghcr.io/woefe/motte/base:latest",
		AllowGroups: []string{"work-vpn"},
		Allow:       []string{"*.internal.example.com"},
	}); err != nil {
		t.Fatal(err)
	}

	var outBuf, errBuf bytes.Buffer
	if err := runPoliciesLs(&outBuf, &errBuf); err != nil {
		t.Fatalf("runPoliciesLs: %v", err)
	}
	stdout, stderr := outBuf.String(), errBuf.String()
	if !strings.Contains(stdout, "group empty-group:\n  (no entries)\n\ngroup work-vpn:\n  *.corp.example.com\n") {
		t.Errorf("stdout = %q, want group listings", stdout)
	}
	wantEffectiveHeader := fmt.Sprintf("effective policy (project %s):\n", hash)
	if !strings.Contains(stdout, wantEffectiveHeader) ||
		!strings.Contains(stdout, "  *.corp.example.com\n  *.internal.example.com\n") {
		t.Errorf("stdout = %q, want effective policy section", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want none", stderr)
	}
}

// TestPoliciesLsEmpty prints the create hint when no group or project exists.
func TestPoliciesLsEmpty(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	var outBuf, errBuf bytes.Buffer
	if err := runPoliciesLs(&outBuf, &errBuf); err != nil {
		t.Errorf("runPoliciesLs: %v", err)
	}
	stdout, stderr := outBuf.String(), errBuf.String()
	if stdout != "" {
		t.Errorf("stdout = %q, want none", stdout)
	}
	if !strings.Contains(stderr, "no policy groups or project configured") {
		t.Errorf("stderr = %q, want the create hint", stderr)
	}
}

// TestPoliciesLsReportsUnreadableGroups shows a group's parse error under its
// header.
func TestPoliciesLsReportsUnreadableGroups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", "allow: [oops\n")
	var outBuf, errBuf bytes.Buffer
	if err := runPoliciesLs(&outBuf, &errBuf); err != nil {
		t.Errorf("runPoliciesLs: %v", err)
	}
	stdout := outBuf.String()
	if !strings.HasPrefix(stdout, "group work-vpn:\n  <unreadable: ") {
		t.Errorf("stdout = %q, want the unreadable group", stdout)
	}
}
