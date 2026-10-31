package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// writePolicyFile writes a file into $XDG_CONFIG_HOME/motte/policies, the
// directory the launcher reads policies from.
func writePolicyFile(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyScopesMapToFiles maps the scopes to their files: global, one
// profile, and the current directory's project file.
func TestPolicyScopesMapToFiles(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		target policyTarget
		want   string
	}{
		{target: policyTarget{scope: scopePolicyGlobal}, want: "global.yaml"},
		{target: policyTarget{scope: scopePolicyProfile, profile: "golang"}, want: "golang.yaml"},
		{target: policyTarget{scope: scopePolicyProject, hash: hash}, want: hash + ".yaml"},
	}
	for _, test := range tests {
		path, err := policyTargetPath(test.target)
		if err != nil {
			t.Fatalf("policyTargetPath: %v", err)
		}
		if filepath.Base(path) != test.want {
			t.Errorf("path = %q, want %q", filepath.Base(path), test.want)
		}
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
	writePolicyFile(t, "global.yaml", `network:
  allow:
    - "extra.example.com"
    - "*.github.com"
`)
	writePolicyFile(t, "golang.yaml", `network:
  allow:
    - "*.github.com"
    - "one.more.example.com"
`)
	writePolicyFile(t, hash+".yaml", `network:
  allow:
    - "project.example.com"
`)
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
	for _, entry := range []string{"*.github.com", "extra.example.com"} {
		if n := countEntries(allow, entry); n != 1 {
			t.Errorf("%q appears %d times, want once", entry, n)
		}
	}
	// 16 base + 5 golang extras + 3 unique user entries.
	if len(allow) != 24 {
		t.Errorf("allow len = %d, want 24", len(allow))
	}
}

// countEntries counts exact occurrences of entry in allow.
func countEntries(allow []string, entry string) int {
	n := 0
	for _, listed := range allow {
		if listed == entry {
			n++
		}
	}
	return n
}

// TestPolicyAllowAbsentAndEmptyNoOps: no policy files, an empty file, and
// an explicitly empty allow list do not change the built-in policy — in
// particular an empty list must not resolve to the public profile.
func TestPolicyAllowAbsentAndEmptyNoOps(t *testing.T) {
	isolatedConfigDir(t)
	writePolicyFile(t, "web.yaml", "")
	profile, err := loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty file: %v", err)
	}
	if len(*profile.network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*profile.network.Allow))
	}

	writePolicyFile(t, "web.yaml", `network:
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
	writePolicyFile(t, "web.yaml", `network:
  alow:
    - "extra.example.com"
`)
	_, err := loadProfile("web")
	if err == nil || !strings.Contains(err.Error(), "invalid policy") || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `alow`", err)
	}

	// The TLS toggle is not part of the policy schema either.
	isolatedConfigDir(t)
	writePolicyFile(t, "global.yaml", `network:
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
	writePolicyFile(t, "golang.yaml", `network:
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
	writePolicyFile(t, "golang.yaml", `network:
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

// TestSandboxOptionsCarryThePolicyFingerprint puts the fingerprint into the
// sandbox labels, so a reused VM can be compared with it.
func TestSandboxOptionsCarryThePolicyFingerprint(t *testing.T) {
	isolatedConfigDir(t)
	profile, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	opts, err := sandboxOptions(profile, false)
	if err != nil {
		t.Fatalf("sandboxOptions: %v", err)
	}
	labels := applyOptions(opts).Labels
	if got := labels[policyLabelKey]; got != policyFingerprint(profile) {
		t.Errorf("label %q = %q, want %q", policyLabelKey, got, policyFingerprint(profile))
	}
}

// TestPoliciesConfigureCreatesTheTemplate covers the configure command: it
// creates a missing scope file from the template and validates it afterwards.
func TestPoliciesConfigureCreatesTheTemplate(t *testing.T) {
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
	if err := runPoliciesConfigure("global"); err != nil {
		t.Fatalf("runPoliciesConfigure: %v", err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies", "global.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the policy file: %v", err)
	}
	if !strings.Contains(string(content), "network:") {
		t.Errorf("policy file = %q, want the template", string(content))
	}
	entries, err := readPolicyFile(path)
	if err != nil {
		t.Fatalf("readPolicyFile: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
}

// TestPoliciesConfigureCreatesTheProjectTemplate covers the project scope: the
// template names the directory the policy belongs to.
func TestPoliciesConfigureCreatesTheProjectTemplate(t *testing.T) {
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
	if err := runPoliciesConfigure("project"); err != nil {
		t.Fatalf("runPoliciesConfigure: %v", err)
	}
	path, err := policyTargetPath(policyTarget{scope: scopePolicyProject, hash: mustDirHash(t)})
	if err != nil {
		t.Fatalf("policyTargetPath: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the policy file: %v", err)
	}
	project, err := projectPath()
	if err != nil {
		t.Fatalf("projectPath: %v", err)
	}
	if !strings.Contains(string(content), "Project path: "+project) {
		t.Errorf("policy file = %q, want the project path", string(content))
	}
}

// mustDirHash returns the hash of the current directory.
func mustDirHash(t *testing.T) string {
	t.Helper()
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// TestPoliciesConfigureRejectsAnInvalidFile covers the validation after the
// editor exits.
func TestPoliciesConfigureRejectsAnInvalidFile(t *testing.T) {
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
	writePolicyFile(t, "global.yaml", "network:\n  alow:\n    - \"extra.example.com\"\n")
	err := runPoliciesConfigure("global")
	if err == nil {
		t.Fatal("error = nil, want an invalid-file failure")
	}
	var coded exitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != 1 {
		t.Errorf("error = %v, want exit code 1", err)
	}
}

// TestPoliciesConfigureRejectsAnUnknownScope rejects a scope that is neither
// global, project, a profile, nor a project hash.
func TestPoliciesConfigureRejectsAnUnknownScope(t *testing.T) {
	isolatedConfigDir(t)
	err := runPoliciesConfigure("bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("error = %v, want an unknown-scope error", err)
	}
}

// TestPoliciesConfigureCreatesTheTemplateForAHash covers a project scope
// addressed by hash: the template is created without a project path, since
// motte cannot know that directory.
func TestPoliciesConfigureCreatesTheTemplateForAHash(t *testing.T) {
	isolatedConfigDir(t)
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
	if err := runPoliciesConfigure("1234567890ab"); err != nil {
		t.Fatalf("runPoliciesConfigure: %v", err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies", "1234567890ab.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the policy file: %v", err)
	}
	if !strings.Contains(string(content), "project 1234567890ab") {
		t.Errorf("policy file = %q, want the hash in the header", string(content))
	}
	if strings.Contains(string(content), "Project path:") {
		t.Errorf("policy file = %q, want no project path for a foreign hash", string(content))
	}
}

// TestCollectPolicyRows lists every scope that applies to a launch, with the
// entries of the files that exist.
func TestCollectPolicyRows(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, "global.yaml", "network:\n  allow:\n    - \"global.example.com\"\n")
	writePolicyFile(t, hash+".yaml", "network:\n  allow:\n    - \"project.example.com\"\n")
	rows, err := collectPolicyRows()
	if err != nil {
		t.Fatalf("collectPolicyRows: %v", err)
	}
	var globalRows, projectRows, missingRows int
	for _, row := range rows {
		switch {
		case row.target.scope == scopePolicyGlobal:
			globalRows++
			if len(row.entries) != 1 || row.entries[0] != "global.example.com" {
				t.Errorf("global entries = %v", row.entries)
			}
		case row.target.scope == scopePolicyProject && row.target.hash == hash:
			projectRows++
			if len(row.entries) != 1 || row.entries[0] != "project.example.com" {
				t.Errorf("project entries = %v", row.entries)
			}
		case !row.exists:
			missingRows++
		}
	}
	if globalRows != 1 || projectRows != 1 {
		t.Errorf("rows = %d global, %d project, want one of each", globalRows, projectRows)
	}
	if missingRows != len(availableProfiles()) {
		t.Errorf("missing rows = %d, want one per profile", missingRows)
	}
}
