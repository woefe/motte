package main

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// workingDir returns the test process's working directory: the base the
// launcher resolves relative mount sources against.
func workingDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return wd
}

// isolatedConfigDir points XDG_CONFIG_HOME at a fresh temp dir so tests never
// read a real ~/.config/motte.
func isolatedConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// captureOutput runs f with stdout and stderr piped, and returns what was
// printed on each. Only for outputs far below the pipe buffer.
func captureOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	originalStdout, originalStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	f()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = originalStdout, originalStderr
	stdoutData, _ := io.ReadAll(stdoutReader)
	stderrData, _ := io.ReadAll(stderrReader)
	return string(stdoutData), string(stderrData)
}

// builtinImages returns the image reference of every built-in profile.
func builtinImages() map[string]string {
	return map[string]string{
		"base":   "ghcr.io/woefe/motte/base:latest",
		"golang": "ghcr.io/woefe/motte/golang:latest",
		"rails":  "ghcr.io/woefe/motte/rails:latest",
		"web":    "ghcr.io/woefe/motte/web:latest",
	}
}

// TestBuiltinProfilesLoad loads every built-in profile and checks what only
// the profile layer carries: the profile's own name and its egress policy.
// The settings a launch applies are checked on the sandbox config in
// TestSandboxOptionsTranslateProfile.
func TestBuiltinProfilesLoad(t *testing.T) {
	isolatedConfigDir(t)
	for name := range builtinImages() {
		t.Run(name, func(t *testing.T) {
			profile, err := loadProfile(name)
			if err != nil {
				t.Fatalf("loadProfile(%s): %v", name, err)
			}
			if profile.name != name {
				t.Errorf("name = %q, want %q", profile.name, name)
			}
			if profile.network == nil || profile.network.Allow == nil ||
				len(*profile.network.Allow) == 0 {
				t.Fatal("network.allow empty")
			}
			// Every profile extends the base policy; extras stay in their owning
			// profiles, and nothing repeats.
			assertAllowListed(t, *profile.network.Allow,
				"dns", "*.github.com", "*.opencode.ai", "host:tcp:9931", "pypi.org")
			// registry.npmjs.org serves the node toolchain in web and rails.
			exclusive := map[string][]string{
				"go.dev":             {"golang"},
				"registry.npmjs.org": {"web", "rails"},
				"rubygems.org":       {"rails"},
				"index.rubygems.org": {"rails"},
			}
			for target, owners := range exclusive {
				if slices.Contains(owners, name) && !slices.Contains(*profile.network.Allow, target) {
					t.Errorf("%s: allow misses its extra %q", name, target)
				}
				if !slices.Contains(owners, name) && slices.Contains(*profile.network.Allow, target) {
					t.Errorf("%s: allow carries %s's extra %q", name, strings.Join(owners, ","), target)
				}
			}
			wantLen := map[string]int{"base": 16, "golang": 21, "rails": 19, "web": 17}[name]
			if len(*profile.network.Allow) != wantLen {
				t.Errorf("allow len = %d, want %d", len(*profile.network.Allow), wantLen)
			}
			assertAllowUnique(t, *profile.network.Allow)
		})
	}
}

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

// TestLoadProfileUnknownProfile rejects a profile the binary does not ship.
func TestLoadProfileUnknownProfile(t *testing.T) {
	isolatedConfigDir(t)
	_, err := loadProfile("python")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") ||
		!strings.Contains(err.Error(), "base, golang, rails, web") {
		t.Fatalf("loadProfile(python) error = %v, want an unknown-profile error listing base, golang, rails, web", err)
	}
}
