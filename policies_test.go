package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// assertAllowListed fails unless each target appears in the allow list.
func assertAllowListed(t *testing.T, allow []string, targets ...string) {
	t.Helper()
	for _, target := range targets {
		if slices.Contains(allow, target) {
			continue
		}
		t.Errorf("allow list misses %q; got %v", target, allow)
	}
}

// assertAllowUnique fails when the allow list repeats an entry.
func assertAllowUnique(t *testing.T, allow []string) {
	t.Helper()
	seen := make(map[string]bool, len(allow))
	for _, entry := range allow {
		if seen[entry] {
			t.Errorf("allow has duplicate %q", entry)
		}
		seen[entry] = true
	}
}

// TestResolveScopeArg accepts the global scope, the project scope, the
// built-in profiles, and a project hash, and rejects everything else.
func TestResolveScopeArg(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		arg        string
		want       scopeArg
		wantTarget policyTarget
	}{
		{arg: "global", wantTarget: policyTarget{scope: scopePolicyGlobal}},
		{
			arg: "project", want: scopeArg{hash: hash},
			wantTarget: policyTarget{scope: scopePolicyProject, hash: hash},
		},
		{
			arg: "golang", want: scopeArg{profile: "golang"},
			wantTarget: policyTarget{scope: scopePolicyProfile, profile: "golang"},
		},
		{
			arg: "1234567890ab", want: scopeArg{hash: "1234567890ab"},
			wantTarget: policyTarget{scope: scopePolicyProject, hash: "1234567890ab"},
		},
	}
	for _, test := range tests {
		t.Run(test.arg, func(t *testing.T) {
			got, err := resolveScopeArg(test.arg)
			if err != nil {
				t.Fatalf("resolveScopeArg: %v", err)
			}
			if got != test.want {
				t.Errorf("resolveScopeArg(%q) = %+v, want %+v", test.arg, got, test.want)
			}
			if target := policyTargetFromArg(got); target != test.wantTarget {
				t.Errorf("policyTargetFromArg(%+v) = %+v, want %+v", got, target, test.wantTarget)
			}
		})
	}
	if _, err := resolveScopeArg("bogus"); err == nil ||
		!strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("error = %v, want an unknown-scope error", err)
	}
}

// TestPolicyAllowExtendsAndDedups appends the user entries after the
// built-in list, deduplicating across the scopes and with the built-ins.
func TestPolicyAllowExtendsAndDedups(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, "policies/global.yaml", fixture(t, "policies/extends/global.yaml"))
	writeConfigFile(t, "policies/golang.yaml", fixture(t, "policies/extends/golang.yaml"))
	writeConfigFile(t, "policies/"+hash+".yaml", fixture(t, "policies/extends/project.yaml"))
	profile, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	allow := *profile.network.Allow
	// Built-ins stay first; the user entries append last, global before
	// profile before project.
	if got := allow[len(allow)-3:]; got[0] != "extra.example.com" ||
		got[1] != "one.more.example.com" || got[2] != "project.example.com" {
		t.Errorf("last entries = %v, want the global, profile, and project entries", got)
	}
	// Cross-scope and built-in duplicates are dropped: the list stays unique.
	assertAllowUnique(t, allow)
	// 16 base + 5 golang extras + 3 unique user entries.
	if len(allow) != 24 {
		t.Errorf("allow len = %d, want 24", len(allow))
	}
}

// TestPolicyAllowAbsentAndEmptyNoOps: no policy files, an empty file, and
// an explicitly empty allow list do not change the built-in policy — in
// particular an empty list must not resolve to the public profile.
func TestPolicyAllowAbsentAndEmptyNoOps(t *testing.T) {
	isolatedConfigDir(t)
	writeConfigFile(t, "policies/web.yaml", "")
	profile, err := loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty file: %v", err)
	}
	if len(*profile.network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*profile.network.Allow))
	}

	writeConfigFile(t, "policies/web.yaml", `network:
  allow: []
`)
	profile, err = loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty allow list: %v", err)
	}
	if len(*profile.network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*profile.network.Allow))
	}
	opts, err := sandboxOptions(profile, false)
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
	isolatedConfigDir(t)
	writeConfigFile(t, "policies/web.yaml", `network:
  alow:
    - "extra.example.com"
`)
	_, err := loadProfile("web")
	if err == nil || !strings.Contains(err.Error(), "invalid policy") || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `alow`", err)
	}

	// The TLS toggle is not part of the policy schema either.
	isolatedConfigDir(t)
	writeConfigFile(t, "policies/global.yaml", `network:
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
	isolatedConfigDir(t)
	writeConfigFile(t, "policies/golang.yaml", `network:
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
	isolatedConfigDir(t)
	profile, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	before := policyFingerprint(profile)
	if before == "" {
		t.Fatal("fingerprint is empty")
	}
	if again := policyFingerprint(profile); again != before {
		t.Errorf("fingerprint = %q, want the stable %q", again, before)
	}
	writeConfigFile(t, "policies/golang.yaml", `network:
  allow:
    - "extra.example.com"
`)
	profile, err = loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if after := policyFingerprint(profile); after == before {
		t.Errorf("fingerprint = %q, want a change after the policy changed", after)
	}
}

// TestPolicyTemplate covers the scope-file skeletons: the entry comments, and
// the project path only for the current directory's project scope.
func TestPolicyTemplate(t *testing.T) {
	isolatedConfigDir(t)
	global, err := policyTemplate(policyTarget{scope: scopePolicyGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(global, "network:") || !strings.Contains(global, "rule grammar") {
		t.Errorf("global template = %q, want the entry comments", global)
	}
	project, err := policyTemplate(policyTarget{scope: scopePolicyProject, hash: mustDirHash(t)})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := projectPath()
	if err != nil {
		t.Fatalf("projectPath: %v", err)
	}
	if !strings.Contains(project, "Project path: "+dir) {
		t.Errorf("project template = %q, want the current directory's path", project)
	}
	foreign, err := policyTemplate(policyTarget{scope: scopePolicyProject, hash: "1234567890ab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(foreign, "Project path:") {
		t.Errorf("foreign template = %q, want no project path", foreign)
	}
}

// TestPoliciesConfigureCreatesTheTemplate covers the configure command: a
// missing scope file is created from the template and validates afterwards,
// for the global scope, this directory's project scope, and a foreign hash.
func TestPoliciesConfigureCreatesTheTemplate(t *testing.T) {
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
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
		entries, err := readPolicyFile(path)
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
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
	writeConfigFile(t, "policies/global.yaml", "network:\n  alow:\n    - \"extra.example.com\"\n")
	err := runPoliciesConfigure("global")
	if err == nil {
		t.Fatal("error = nil, want an invalid-file failure")
	}
	var coded exitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != 1 {
		t.Errorf("error = %v, want exit code 1", err)
	}
}

// TestLsScopesSkipsNonScopeFiles lists only the files whose names are a scope:
// a directory, a wrong extension, and an unknown name are all skipped, and a
// config tree that does not exist yet holds no scopes. The order of the
// scopes is pinned by the ls command tests.
func TestLsScopesSkipsNonScopeFiles(t *testing.T) {
	isolatedConfigDir(t)
	root := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies")
	for _, name := range []string{"global.yaml", "golang.yaml", "1234567890ab.yaml", "bogus.yaml", "global.yml"} {
		writeConfigFile(t, "policies/"+name, "")
	}
	if err := os.Mkdir(filepath.Join(root, "archive.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	scopes, err := lsScopes(root)
	if err != nil {
		t.Fatalf("lsScopes: %v", err)
	}
	want := []scopeArg{{}, {profile: "golang"}, {hash: "1234567890ab"}}
	if !slices.Equal(scopes, want) {
		t.Errorf("scopes = %+v, want %+v", scopes, want)
	}
	if scopes, err = lsScopes(filepath.Join(root, "missing")); err != nil || scopes != nil {
		t.Errorf("lsScopes(missing) = %+v %v, want none without an error", scopes, err)
	}
}

// TestPoliciesLsListsGroups covers the grouped listing: only scopes with
// files, blank lines between groups, the current-directory mark, and
// placeholder bodies.
func TestPoliciesLsListsGroups(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	writeConfigFile(t, "policies/global.yaml", fixture(t, "policies/ls/global.yaml"))
	writeConfigFile(t, "policies/golang.yaml", "network:\n  allow: []\n")
	writeConfigFile(t, "policies/"+hash+".yaml", fixture(t, "policies/ls/project.yaml"))
	writeConfigFile(t, "policies/ffffffffffff.yaml", fixture(t, "policies/ls/foreign.yaml"))
	stdout, stderr := captureOutput(t, func() {
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
	isolatedConfigDir(t)
	stdout, stderr := captureOutput(t, func() {
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
	isolatedConfigDir(t)
	writeConfigFile(t, "policies/global.yaml", "network: [oops\n")
	stdout, _ := captureOutput(t, func() {
		if err := runPoliciesLs(); err != nil {
			t.Errorf("runPoliciesLs: %v", err)
		}
	})
	if !strings.HasPrefix(stdout, "global:\n  <unreadable: ") {
		t.Errorf("stdout = %q, want the unreadable group", stdout)
	}
}
