package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// writeUserConfig writes a file into $XDG_CONFIG_HOME/motte, the directory the
// launcher reads user config from.
func writeUserConfig(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestUserAllowExtendsAndDedups appends user entries after the built-in list,
// deduplicating across files and with the built-ins.
func TestUserAllowExtendsAndDedups(t *testing.T) {
	isolatedConfigDir(t)
	writeUserConfig(t, "common.yaml", `network:
  allow:
    - "extra.example.com"
    - "*.github.com"
`)
	writeUserConfig(t, "golang.yaml", `network:
  allow:
    - "*.github.com"
    - "one.more.example.com"
`)
	profile, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	allow := *profile.network.Allow
	// Built-ins stay first; the user entries append last, common before profile.
	if got := allow[len(allow)-2:]; got[0] != "extra.example.com" || got[1] != "one.more.example.com" {
		t.Errorf("last entries = %v, want extra.example.com then one.more.example.com", got)
	}
	for _, entry := range []string{"*.github.com", "extra.example.com"} {
		if n := countEntries(allow, entry); n != 1 {
			t.Errorf("%q appears %d times, want once", entry, n)
		}
	}
	// 16 base + 5 golang extras + 2 unique user entries.
	if len(allow) != 23 {
		t.Errorf("allow len = %d, want 23", len(allow))
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

// TestUserAllowAbsentAndEmptyNoOps: no user files, an empty file, and an
// explicitly empty allow list do not change the built-in policy — in
// particular an empty list must not resolve to the public profile.
func TestUserAllowAbsentAndEmptyNoOps(t *testing.T) {
	isolatedConfigDir(t)
	writeUserConfig(t, "web.yaml", "")
	profile, err := loadProfile("web")
	if err != nil {
		t.Fatalf("loadProfile with an empty file: %v", err)
	}
	if len(*profile.network.Allow) != 17 {
		t.Errorf("allow len = %d, want the unchanged 17", len(*profile.network.Allow))
	}

	writeUserConfig(t, "web.yaml", `network:
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

// TestUserAllowRejectsUnknownFields fails the launch on a schema typo.
func TestUserAllowRejectsUnknownFields(t *testing.T) {
	isolatedConfigDir(t)
	writeUserConfig(t, "web.yaml", `network:
  alow:
    - "extra.example.com"
`)
	_, err := loadProfile("web")
	if err == nil || !strings.Contains(err.Error(), "user config") || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `alow`", err)
	}

	// The TLS toggle is not part of the user schema either.
	isolatedConfigDir(t)
	writeUserConfig(t, "common.yaml", `network:
  tls:
    enabled: false
`)
	_, err = loadProfile("golang")
	if err == nil || !strings.Contains(err.Error(), "user config") || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("error = %v, want an unknown-field error naming the file and `tls`", err)
	}
}

// TestUserAllowRejectsBadRuleEntries validates entries with the CLI rule
// grammar at load time, with the file named in the error.
func TestUserAllowRejectsBadRuleEntries(t *testing.T) {
	isolatedConfigDir(t)
	writeUserConfig(t, "golang.yaml", `network:
  allow:
    - "*.github.com"
    - "webserver"
`)
	_, err := loadProfile("golang")
	if err == nil || !strings.Contains(err.Error(), "user config") || !strings.Contains(err.Error(), "webserver") {
		t.Fatalf("error = %v, want a bad-rule error naming the file and `webserver`", err)
	}
}
