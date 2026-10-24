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

// fixtureEnv returns getenv returning sk_test for the declared secret.
func fixtureEnv(envVar string) string {
	if envVar == "OPENCODE_GO_KEY" {
		return "sk_test"
	}
	return ""
}

// TestBuiltinProfilesLoad loads every built-in profile and checks the shared
// base plus the launch-time resolution: cwd-relative mounts, env-fed secrets,
// and the static sanity of the definitions.
func TestBuiltinProfilesLoad(t *testing.T) {
	images := map[string]string{
		"golang": "ghcr.io/woefe/motte/golang:latest",
		"web":    "ghcr.io/woefe/motte/web:latest",
	}
	for name, image := range images {
		t.Run(name, func(t *testing.T) {
			profile, err := loadProfile(name, fixtureEnv)
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
			assertAllowListed(t, *profile.network.Allow, "*.github.com", "host:tcp:9931")

			// The secret resolves from the host environment.
			if len(profile.secrets) != 1 {
				t.Fatalf("secrets = %+v, want 1", profile.secrets)
			}
			secret := profile.secrets[0]
			if secret.envVar != "OPENCODE_GO_KEY" || secret.value != "sk_test" {
				t.Errorf("secret = %q %q", secret.envVar, secret.value)
			}
			if len(secret.allow) != 1 || secret.allow[0] != "*.opencode.ai" {
				t.Errorf("secret.allow = %v", secret.allow)
			}
			if len(secret.headerFields) != 2 || secret.headerFields[0] != "authorization" {
				t.Errorf("headerFields = %v", secret.headerFields)
			}
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
	_, err := loadProfile("rails", fixtureEnv)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") ||
		!strings.Contains(err.Error(), "golang, web") {
		t.Fatalf("loadProfile(rails) error = %v, want an unknown-profile error listing golang, web", err)
	}
}

// TestLoadProfileRequiresSecretValue fails without the host env var set.
func TestLoadProfileRequiresSecretValue(t *testing.T) {
	_, err := loadProfile("golang", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "OPENCODE_GO_KEY") {
		t.Fatalf("error = %v, want a missing-env error naming OPENCODE_GO_KEY", err)
	}
}
