package launcher

import (
	"os"
	"slices"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// swapStore replaces the default keychain store, restoring it at cleanup.
func swapStore(t *testing.T, store secrets.Store) {
	t.Helper()
	original := secrets.DefaultStore
	secrets.DefaultStore = store
	t.Cleanup(func() { secrets.DefaultStore = original })
}

// TestPolicyAllowExtendsAndDedups appends the user entries after the
// built-in list, deduplicating across the scopes and with the built-ins.
func TestPolicyAllowExtendsAndDedups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteConfigFile(t, "policies/global.yaml", testutil.Fixture(t, "policies/extends/global.yaml"))
	testutil.WriteConfigFile(t, "policies/golang.yaml", testutil.Fixture(t, "policies/extends/golang.yaml"))
	testutil.WriteConfigFile(t, "policies/"+hash+".yaml", testutil.Fixture(t, "policies/extends/project.yaml"))
	p, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	allow := *p.Network.Allow
	// Built-ins stay first; the user entries append last, global before
	// profile before project.
	if got := allow[len(allow)-3:]; got[0] != "extra.example.com" ||
		got[1] != "one.more.example.com" || got[2] != "project.example.com" {
		t.Errorf("last entries = %v, want the global, profile, and project entries", got)
	}
	// Cross-scope and built-in duplicates are dropped: the list stays unique.
	testutil.AssertAllowUnique(t, allow)
	// 16 base + 5 golang extras + 3 unique user entries.
	if len(allow) != 24 {
		t.Errorf("allow len = %d, want 24", len(allow))
	}
}

// TestPolicyAllowAbsentAndEmptyNoOps: no policy files, an empty file, and
// an explicitly empty allow list do not change the built-in policy — in
// particular an empty list must not resolve to the public profile.
func TestPolicyAllowAbsentAndEmptyNoOps(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/web.yaml", "")
	p, err := loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty file: %v", err)
	}
	if len(*p.Network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*p.Network.Allow))
	}

	testutil.WriteConfigFile(t, "policies/web.yaml", `network:
  allow: []
`)
	p, err = loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty allow list: %v", err)
	}
	if len(*p.Network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*p.Network.Allow))
	}
	opts, err := sandboxOptions(p, false)
	if err != nil {
		t.Fatalf("sandboxOptions: %v", err)
	}
	config := applyOptions(opts)
	if config.Network == nil || config.Network.DefaultEgress != m.PolicyActionDeny {
		t.Errorf("Network = %+v, want deny-by-default, not the public profile", config.Network)
	}
}

// TestPolicyRejectsUnknownFields fails the launch on a schema typo.
func TestPolicyRejectsUnknownFields(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/web.yaml", `network:
  alow:
    - "extra.example.com"
`)
	_, err := loadProfile("web")
	if err == nil || !strings.Contains(err.Error(), "invalid policy") || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `alow`", err)
	}

	// The TLS toggle is not part of the policy schema either.
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/global.yaml", `network:
  tls:
    enabled: false
`)
	_, err = loadProfile("golang")
	if err == nil || !strings.Contains(err.Error(), "invalid policy") || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `tls`", err)
	}
}

// TestPolicyRejectsBadRuleEntries validates the entries with the CLI rule
// grammar at load time, with the file named in the error.
func TestPolicyRejectsBadRuleEntries(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/golang.yaml", `network:
  allow:
    - "*.github.com"
    - "webserver"
`)
	_, err := loadProfile("golang")
	if err == nil || !strings.Contains(err.Error(), "policy") || !strings.Contains(err.Error(), "webserver") {
		t.Fatalf("error = %v, want a bad-rule error naming the file and `webserver`", err)
	}
}

// TestPolicyFingerprintChangesWithThePolicy covers the fingerprint that
// rides in the sandbox label: it changes with the policy and stays the same
// for an unchanged one.
func TestPolicyFingerprintChangesWithThePolicy(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	p, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	before := policies.Fingerprint(p)
	if before == "" {
		t.Fatal("fingerprint is empty")
	}
	if again := policies.Fingerprint(p); again != before {
		t.Errorf("fingerprint = %q, want the stable %q", again, before)
	}
	testutil.WriteConfigFile(t, "policies/golang.yaml", `network:
  allow:
    - "extra.example.com"
`)
	p, err = loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if after := policies.Fingerprint(p); after == before {
		t.Errorf("fingerprint = %q, want a change after the policy changed", after)
	}
}

// TestResolveSecrets: values come from the keychain into host env vars, egress
// extends with the secrets' allow entries, and a keychain-less secret fails
// the launch with the set hint.
func TestResolveSecrets(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"OPENCODE_GO_KEY": "sk_test"}))
	testutil.WriteConfigFile(t, "secrets/global.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow:\n      - \"*.opencode.ai\"\n")
	t.Cleanup(func() { _ = os.Unsetenv("MOTTE_SECRET_OPENCODE_GO_KEY") })

	p, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	resolved, err := resolveSecrets(p)
	if err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	if len(resolved) != 1 || resolved[0].Name != "OPENCODE_GO_KEY" {
		t.Fatalf("resolveSecrets = %+v", resolved)
	}
	if got := os.Getenv("MOTTE_SECRET_OPENCODE_GO_KEY"); got != "sk_test" {
		t.Errorf("MOTTE_SECRET_OPENCODE_GO_KEY = %q", got)
	}
	// Egress auto-extends with the secrets' allow entries.
	if !slices.Contains(*p.Network.Allow, "*.opencode.ai") {
		t.Errorf("allow misses the secret's host: %v", *p.Network.Allow)
	}
	unsetSecretEnv(resolved)
	if got := os.Getenv("MOTTE_SECRET_OPENCODE_GO_KEY"); got != "" {
		t.Errorf("env still set after unsetting: %q", got)
	}

	// Without a keychain value the launch fails with a set hint.
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, nil))
	if _, err := resolveSecrets(p); err == nil ||
		!strings.Contains(err.Error(), "motte secrets set OPENCODE_GO_KEY") {
		t.Errorf("error = %v, want the set hint", err)
	}
}
