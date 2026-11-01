package main

import (
	"slices"
	"strings"
	"testing"
)

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

// TestLoadProfileUnknownProfile rejects a profile the binary does not ship.
func TestLoadProfileUnknownProfile(t *testing.T) {
	isolatedConfigDir(t)
	_, err := loadProfile("python")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") ||
		!strings.Contains(err.Error(), "base, golang, rails, web") {
		t.Fatalf("loadProfile(python) error = %v, want an unknown-profile error listing base, golang, rails, web", err)
	}
}
