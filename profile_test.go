package main

import (
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

// builtinImages returns the image reference of every built-in profile.
func builtinImages() map[string]string {
	return map[string]string{
		"golang": "ghcr.io/woefe/motte/golang:latest",
		"web":    "ghcr.io/woefe/motte/web:latest",
	}
}

// TestBuiltinProfilesLoad loads every built-in profile and checks the shared
// base plus the launch-time resolution: cwd-relative mounts and the static
// sanity of the definitions.
func TestBuiltinProfilesLoad(t *testing.T) {
	isolatedConfigDir(t)
	images := builtinImages()
	for name, image := range images {
		t.Run(name, func(t *testing.T) {
			profile, err := loadProfile(name)
			if err != nil {
				t.Fatalf("loadProfile(%s): %v", name, err)
			}

			// The base() settings compose with the profile's own overrides.
			if profile.name != name {
				t.Errorf("name = %q, want %q", profile.name, name)
			}
			if profile.image != image {
				t.Errorf("image = %q, want %q", profile.image, image)
			}
			if profile.cpus == nil || *profile.cpus != 4 {
				t.Errorf("cpus = %v", profile.cpus)
			}
			if profile.memoryMiB == nil || *profile.memoryMiB != 4096 {
				t.Errorf("memoryMiB = %v", profile.memoryMiB)
			}
			if profile.workdir == nil || *profile.workdir != "/workspace" {
				t.Errorf("workdir = %v", profile.workdir)
			}
			if profile.shell == nil || *profile.shell != "/bin/bash" {
				t.Errorf("shell = %v", profile.shell)
			}
			if len(profile.cmd) != 1 || profile.cmd[0] != "opencode" {
				t.Errorf("cmd = %v", profile.cmd)
			}
			if got, ok := profile.scripts["check"]; !ok || !strings.Contains(got, "opencode --version") {
				t.Errorf("scripts.check = %q", got)
			}
			if profile.network == nil || profile.network.TLS == nil ||
				profile.network.TLS.Enabled == nil || !*profile.network.TLS.Enabled {
				t.Error("network.TLS not enabled from base")
			}

			// The mount source resolves cwd-relative: ./ is the directory motte
			// started in.
			if len(profile.mounts) != 1 {
				t.Fatalf("mounts = %+v, want 1", profile.mounts)
			}
			mount := profile.mounts[0]
			if mount.guestPath != "/workspace" {
				t.Errorf("guestPath = %q", mount.guestPath)
			}
			if want := workingDir(t); mount.hostPath != want {
				t.Errorf("hostPath = %q, want %q", mount.hostPath, want)
			}
			if mount.readonly {
				t.Error("mount is readonly, want rw")
			}

			// The profile's own egress policy replaces the base's (base sets none),
			// while TLS stays enabled.
			if profile.network.Allow == nil || len(*profile.network.Allow) == 0 {
				t.Fatal("network.allow empty")
			}
			// Every profile extends the base policy; extras stay in their owning
			// profile, and nothing repeats.
			assertAllowListed(t, *profile.network.Allow,
				"dns", "*.github.com", "*.opencode.ai", "host:tcp:9931", "pypi.org")
			exclusive := map[string]string{"go.dev": "golang", "registry.npmjs.org": "web"}
			for target, owner := range exclusive {
				if name == owner && !slices.Contains(*profile.network.Allow, target) {
					t.Errorf("%s: allow misses its extra %q", name, target)
				}
				if name != owner && slices.Contains(*profile.network.Allow, target) {
					t.Errorf("%s: allow carries %s's extra %q", name, owner, target)
				}
			}
			wantLen := map[string]int{"golang": 21, "web": 17}[name]
			if len(*profile.network.Allow) != wantLen {
				t.Errorf("allow len = %d, want %d", len(*profile.network.Allow), wantLen)
			}
			seen := make(map[string]bool, len(*profile.network.Allow))
			for _, entry := range *profile.network.Allow {
				if seen[entry] {
					t.Errorf("allow has duplicate %q", entry)
				}
				seen[entry] = true
			}

			// Secrets are user-configured for the OS keychain, not part of
			// the built-in profile; covered in secrets_test.go.
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

// TestLoadProfileUnknownProfile rejects a profile the binary does not ship.
func TestLoadProfileUnknownProfile(t *testing.T) {
	isolatedConfigDir(t)
	_, err := loadProfile("rails")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") ||
		!strings.Contains(err.Error(), "golang, web") {
		t.Fatalf("loadProfile(rails) error = %v, want an unknown-profile error listing golang, web", err)
	}
}
