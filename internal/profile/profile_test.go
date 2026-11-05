package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/testutil"
)

// TestBuiltinProfilesLoad loads every built-in profile and checks what only
// the profile layer carries: the profile's own name and its egress policy.
// The settings a launch applies are checked on the sandbox config in the
// launcher's TestSandboxOptionsTranslateProfile.
func TestBuiltinProfilesLoad(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	for name := range testutil.BuiltinImages() {
		t.Run(name, func(t *testing.T) {
			profile, err := Load(name)
			if err != nil {
				t.Fatalf("Load(%s): %v", name, err)
			}
			if profile.Name != name {
				t.Errorf("Name = %q, want %q", profile.Name, name)
			}
			if profile.Network == nil || profile.Network.Allow == nil ||
				len(*profile.Network.Allow) == 0 {
				t.Fatal("network.allow empty")
			}
			// Every profile extends the base policy; extras stay in their owning
			// profiles, and nothing repeats.
			testutil.AssertAllowListed(t, *profile.Network.Allow,
				"dns", "*.github.com", "*.opencode.ai", "pypi.org")
			// registry.npmjs.org serves the node toolchain in web and rails.
			exclusive := map[string][]string{
				"go.dev":             {"golang"},
				"registry.npmjs.org": {"web", "rails"},
				"rubygems.org":       {"rails"},
				"index.rubygems.org": {"rails"},
			}
			for target, owners := range exclusive {
				if slices.Contains(owners, name) && !slices.Contains(*profile.Network.Allow, target) {
					t.Errorf("%s: allow misses its extra %q", name, target)
				}
				if !slices.Contains(owners, name) && slices.Contains(*profile.Network.Allow, target) {
					t.Errorf("%s: allow carries %s's extra %q", name, strings.Join(owners, ","), target)
				}
			}
			wantLen := map[string]int{"base": 15, "golang": 20, "rails": 18, "web": 16}[name]
			if len(*profile.Network.Allow) != wantLen {
				t.Errorf("allow len = %d, want %d", len(*profile.Network.Allow), wantLen)
			}
			testutil.AssertAllowUnique(t, *profile.Network.Allow)
		})
	}
}

// TestLoadUnknownProfile rejects a profile the binary does not ship.
func TestLoadUnknownProfile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	_, err := Load("python")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") ||
		!strings.Contains(err.Error(), "base, golang, rails, web") {
		t.Fatalf("Load(python) error = %v, want an unknown-profile error listing base, golang, rails, web", err)
	}
}
