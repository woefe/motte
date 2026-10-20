package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeProfileFile writes one sandboxes/*.yaml fixture into dir.
func writeProfileFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureEnv returns getenv returning sk_test for the declared secret.
func fixtureEnv(envVar string) string {
	if envVar == "OPENCODE_GO_KEY" {
		return "sk_test"
	}
	return ""
}

// writeGolangFixtures writes a common.yaml and golang.yaml pair mirroring the
// repository's profiles.
func writeGolangFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `cpus: 4
memory: "4G"
workdir: "/workspace"
shell: "/bin/bash"
mounts:
  - "../:/workspace:rw"
network:
  tls:
    enabled: true
secrets:
  OPENCODE_GO_KEY:
    allow:
      - "*.opencode.ai"
    substitution:
      header_fields:
        - authorization
        - x-api-key
scripts:
  check: |
    opencode --version
cmd:
  - opencode
`)
	writeProfileFile(t, dir, "golang.yaml", `image: "ghcr.io/woefe/motte/golang:latest"
network:
  allow:
    - dns
    - "*.github.com"
    - host:tcp:9931
`)
	return dir
}

func TestLoadProfileMergesAndResolves(t *testing.T) {
	dir := writeGolangFixtures(t)
	profile, err := loadProfile(dir, "golang", fixtureEnv)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if profile.image != "ghcr.io/woefe/motte/golang:latest" {
		t.Errorf("image = %q", profile.image)
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
	// The mount source resolves config-relative: ../ from sandboxes/ = repo dir.
	if len(profile.mounts) != 1 {
		t.Fatalf("mounts = %+v, want 1", profile.mounts)
	}
	mount := profile.mounts[0]
	if mount.guestPath != "/workspace" {
		t.Errorf("guestPath = %q", mount.guestPath)
	}
	if want := filepath.Dir(filepath.Clean(dir)); mount.hostPath != want {
		t.Errorf("hostPath = %q, want %q", mount.hostPath, want)
	}
	if mount.readonly {
		t.Error("mount is readonly, want rw")
	}
	// Network allow comes from the profile file, TLS from common.yaml.
	if profile.network == nil || profile.network.Allow == nil || len(*profile.network.Allow) != 3 {
		t.Fatalf("network = %+v", profile.network)
	}
	if profile.network.TLS == nil || profile.network.TLS.Enabled == nil || !*profile.network.TLS.Enabled {
		t.Error("network.TLS not enabled, want enabled from common.yaml")
	}
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
}

func TestOverlayLaterFileWinsFieldByField(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `image: "a:1"
cpus: 2
memory: "2G"
mounts:
  - "./first:/data:ro"
scripts:
  check: "first check"
  extra: "kept"
network:
  allow:
    - "old.example.com"
  tls:
    enabled: true
secrets:
  TOKEN:
    allow:
      - "*.old.example.com"
    substitution:
      header_fields:
        - authorization
  OTHER:
    allow:
      - "other.example.com"
`)
	writeProfileFile(t, dir, "golang.yaml", `image: "b:2"
memory: "8G"
mounts:
  - "./second:/data"
cmd: ["opencode"]
network:
  allow:
    - "new.example.com"
scripts:
  check: "second check"
secrets:
  TOKEN:
    allow:
      - "*.new.example.com"
`)
	profile, err := loadProfile(dir, "golang", func(envVar string) string {
		return "value-" + envVar
	})
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if profile.image != "b:2" {
		t.Errorf("image = %q, want b:2", profile.image)
	}
	if profile.cpus == nil || *profile.cpus != 2 {
		t.Error("cpus should be kept from common.yaml")
	}
	if profile.memoryMiB == nil || *profile.memoryMiB != 8192 {
		t.Errorf("memoryMiB = %v, want 8192", profile.memoryMiB)
	}
	// Vec fields replace wholesale; the mount is re-resolved config-relative.
	if len(profile.mounts) != 1 || profile.mounts[0].guestPath != "/data" ||
		profile.mounts[0].readonly || profile.mounts[0].hostPath != filepath.Join(dir, "second") {
		t.Errorf("mounts = %+v", profile.mounts)
	}
	// Map fields merge per key.
	if got := profile.scripts["extra"]; got != "kept" {
		t.Errorf("scripts.extra = %q, want kept", got)
	}
	if got := profile.scripts["check"]; got != "second check" {
		t.Errorf("scripts.check = %q, want second check", got)
	}
	// network.allow replaces the policy part; network.tls is patched.
	if got := *profile.network.Allow; len(got) != 1 || got[0] != "new.example.com" {
		t.Errorf("allow = %v", got)
	}
	if profile.network.TLS == nil || profile.network.TLS.Enabled == nil || !*profile.network.TLS.Enabled {
		t.Error("network.tls should stay enabled")
	}
	// Secrets merge per name and field; an absent substitution clears to default.
	found := false
	for _, secret := range profile.secrets {
		if secret.envVar != "TOKEN" {
			continue
		}
		found = true
		if len(secret.allow) != 1 || secret.allow[0] != "*.new.example.com" {
			t.Errorf("TOKEN.allow = %v", secret.allow)
		}
		if len(secret.headerFields) != 1 || secret.headerFields[0] != "authorization" {
			t.Errorf("TOKEN.headerFields = %v, want the substituted field kept from common.yaml", secret.headerFields)
		}
	}
	if !found {
		t.Fatal("TOKEN secret missing")
	}
}

func TestLoadProfileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `image: "a:1"
env:
  FOO: bar
`)
	_, err := loadProfile(dir, "golang", fixtureEnv)
	if err == nil || !strings.Contains(err.Error(), "env") {
		t.Fatalf("error = %v, want an unknown-field error mentioning env", err)
	}
}

func TestLoadProfileRequiresImage(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `cmd: ["opencode"]
`)
	writeProfileFile(t, dir, "golang.yaml", `memory: "1G"
`)
	_, err := loadProfile(dir, "golang", fixtureEnv)
	if err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("error = %v, want a missing-image error", err)
	}
}

func TestLoadProfileRequiresSecretValue(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `image: "a:1"
secrets:
  OPENCODE_GO_KEY:
    allow: ["*.opencode.ai"]
`)
	writeProfileFile(t, dir, "golang.yaml", "image: \"a:1\"\n")
	_, err := loadProfile(dir, "golang", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "OPENCODE_GO_KEY") {
		t.Fatalf("error = %v, want a missing-env error naming OPENCODE_GO_KEY", err)
	}
}

func TestLoadProfileRejectsEmptySecretAllowList(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `image: "a:1"
secrets:
  TOKEN: {}
`)
	writeProfileFile(t, dir, "golang.yaml", "image: \"a:1\"\n")
	_, err := loadProfile(dir, "golang", func(string) string { return "v" })
	if err == nil || !strings.Contains(err.Error(), "allow") {
		t.Fatalf("error = %v, want an empty-allow error", err)
	}
}

func TestLoadProfileRejectsDuplicateGuestTargets(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "common.yaml", `image: "a:1"
mounts:
  - "./a:/data"
  - "../:/data"
`)
	writeProfileFile(t, dir, "golang.yaml", "image: \"a:1\"\n")
	_, err := loadProfile(dir, "golang", fixtureEnv)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want a duplicate-target error", err)
	}
}

func TestParseMountSpec(t *testing.T) {
	tests := []struct {
		spec       string
		hostPath   string
		guestPath  string
		readonly   bool
		noexec     bool
		wantErr    bool
		errComment string // substring expected in the error
	}{
		{spec: "../:/workspace:rw", hostPath: "/repo", guestPath: "/workspace", readonly: false},
		{spec: "../:/workspace", hostPath: "/repo", guestPath: "/workspace"},
		{
			spec:      "sub:/data:ro,noexec",
			hostPath:  "/repo/sandboxes/sub",
			guestPath: "/data",
			readonly:  true,
			noexec:    true,
		},
		{spec: "/abs:/data:nosuid", hostPath: "/abs", guestPath: "/data"},
		{spec: "./:/w:ro,rw", wantErr: true, errComment: "conflicting"},
		{spec: "./:/w:quota=1024", wantErr: true, errComment: "unsupported option"},
		{spec: "./:relative", wantErr: true, errComment: "absolute"},
		{spec: "no-colon", wantErr: true, errComment: "SOURCE:TARGET"},
		{spec: ":/data", wantErr: true, errComment: "empty source"},
	}
	for _, test := range tests {
		mount, err := parseMountSpec(test.spec, "/repo/sandboxes")
		if test.wantErr {
			if err == nil || !strings.Contains(err.Error(), test.errComment) {
				t.Errorf("parseMountSpec(%q) error = %v, want containing %q", test.spec, err, test.errComment)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMountSpec(%q) = %v", test.spec, err)
			continue
		}
		if mount.hostPath != test.hostPath || mount.guestPath != test.guestPath {
			t.Errorf("parseMountSpec(%q) = %+v, want %q -> %q", test.spec, mount, test.hostPath, test.guestPath)
		}
		if mount.readonly != test.readonly || mount.noexec != test.noexec {
			t.Errorf("parseMountSpec(%q) options = %+v", test.spec, mount)
		}
	}
}

// TestRealProfilesLoad guards against config edits breaking the launcher.
func TestRealProfilesLoad(t *testing.T) {
	dir := filepath.Join(sourceDir(), "sandboxes")
	for _, name := range []string{"golang", "web"} {
		t.Run(name, func(t *testing.T) {
			profile, err := loadProfile(dir, name, fixtureEnv)
			if err != nil {
				t.Fatalf("loadProfile(%s): %v", name, err)
			}
			if !strings.HasPrefix(profile.image, "ghcr.io/woefe/motte/"+name+":") {
				t.Errorf("image = %q", profile.image)
			}
			if len(profile.mounts) != 1 || profile.mounts[0].guestPath != "/workspace" {
				t.Fatalf("mounts = %+v", profile.mounts)
			}
			if want := filepath.Clean(sourceDir()); profile.mounts[0].hostPath != want {
				t.Errorf("hostPath = %q, want the repo root %q", profile.mounts[0].hostPath, want)
			}
			if len(profile.secrets) != 1 {
				t.Errorf("secrets = %+v, want OPENCODE_GO_KEY", profile.secrets)
			}
			if len(profile.cmd) == 0 {
				t.Error("cmd missing")
			}
		})
	}
}
