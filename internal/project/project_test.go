package project

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// TestPresetsAndDetectPreset checks the built-in image presets and repository
// toolchain detection in precedence order (go.mod -> golang, Gemfile -> rails,
// package.json -> web, else base).
func TestPresetsAndDetectPreset(t *testing.T) {
	wantPresets := []string{"base", "golang", "rails", "web"}
	if got := Presets(); !slices.Equal(got, wantPresets) {
		t.Fatalf("Presets() = %v, want %v", got, wantPresets)
	}
	for name, wantImage := range presets {
		image, ok := PresetImage(name)
		if !ok || image != wantImage {
			t.Errorf("PresetImage(%q) = %q, %v; want %q", name, image, ok, wantImage)
		}
		gotName, ok := PresetName(wantImage)
		if !ok || gotName != name {
			t.Errorf("PresetName(%q) = %q, %v; want %q", wantImage, gotName, ok, name)
		}
	}
	if _, ok := PresetImage("python"); ok {
		t.Error("PresetImage(python) succeeded, want false")
	}
	if _, ok := PresetName("custom.example.com/app:latest"); ok {
		t.Error("PresetName(custom) succeeded, want false")
	}

	dir := t.TempDir()
	if got := DetectPreset(dir); got != "base" {
		t.Errorf("empty dir preset = %q, want base", got)
	}
	touch := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	touch("package.json")
	if got := DetectPreset(dir); got != "web" {
		t.Errorf("with package.json preset = %q, want web", got)
	}
	touch("Gemfile")
	if got := DetectPreset(dir); got != "rails" {
		t.Errorf("with Gemfile + package.json preset = %q, want rails", got)
	}
	touch("go.mod")
	if got := DetectPreset(dir); got != "golang" {
		t.Errorf("with go.mod preset = %q, want golang", got)
	}
}

// TestReadWriteCurrent round-trips the current directory's project config and
// verifies the `# Project path:` comment and 0600 file permissions.
func TestReadWriteCurrent(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	if _, _, err := ReadCurrent(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadCurrent(missing) = %v, want ErrNotFound", err)
	}

	want := Config{
		Image:       "ghcr.io/woefe/motte/golang:latest",
		Allow:       []string{"*.internal.example.com"},
		AllowGroups: []string{"work-vpn"},
		Secrets:     []string{"EXAMPLE_API_KEY"},
	}
	path, err := WriteCurrent(want)
	if err != nil {
		t.Fatalf("WriteCurrent: %v", err)
	}
	got, gotPath, err := ReadCurrent()
	if err != nil {
		t.Fatalf("ReadCurrent: %v", err)
	}
	if gotPath != path {
		t.Errorf("ReadCurrent path = %q, want %q", gotPath, path)
	}
	if got.Image != want.Image || !slices.Equal(got.Allow, want.Allow) ||
		!slices.Equal(got.AllowGroups, want.AllowGroups) || !slices.Equal(got.Secrets, want.Secrets) {
		t.Errorf("ReadCurrent = %+v, want %+v", got, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := config.ProjectPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "# motte project\n# Project path: "+dir+"\n---\n") {
		t.Errorf("file content = %q, want project path header and document marker", string(content))
	}
}

// TestReadFileValidation checks strict YAML validation on project configs.
func TestReadFileValidation(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	path, err := CurrentPath()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	rel := "projects/" + hash + ".yaml"

	tests := []struct {
		name   string
		yaml   string
		wantRe string
	}{
		{name: "empty", yaml: "", wantRe: "image is required"},
		{name: "preset name instead of ref", yaml: "image: golang\n", wantRe: "full image reference"},
		{name: "unknown field", yaml: "image: ghcr.io/woefe/motte/base:latest\nextra: 1\n", wantRe: "extra"},
		{
			name:   "bad network allow",
			yaml:   "image: ghcr.io/woefe/motte/base:latest\nnetwork:\n  allow:\n    - webserver\n",
			wantRe: "webserver",
		},
		{
			name:   "bad group name",
			yaml:   "image: ghcr.io/woefe/motte/base:latest\nnetwork:\n  allowGroups:\n    - Bad_Group\n",
			wantRe: "Bad_Group",
		},
		{
			name:   "bad secret name",
			yaml:   "image: ghcr.io/woefe/motte/base:latest\nsecrets:\n  - bad-secret\n",
			wantRe: "bad-secret",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testutil.WriteConfigFile(t, rel, test.yaml)
			_, err := ReadFile(path)
			if err == nil || !strings.Contains(err.Error(), test.wantRe) || !strings.Contains(err.Error(), path) {
				t.Errorf("ReadFile(%s) = %v, want error containing %q and path %q", test.name, err, test.wantRe, path)
			}
		})
	}
}

// TestEffectiveAllowExtendsAndDedups merges selected policy groups and
// project allow entries in order, deduplicating.
func TestEffectiveAllowExtendsAndDedups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/corp.yaml", "allow:\n  - \"*.github.com\"\n  - \"corp.example.com\"\n")
	testutil.WriteConfigFile(t, "policies/vpn.yaml", "allow:\n  - \"corp.example.com\"\n  - \"vpn.example.com\"\n")

	proj := Config{
		Image:       "ghcr.io/woefe/motte/golang:latest",
		AllowGroups: []string{"corp", "vpn"},
		Allow:       []string{"vpn.example.com", "project.example.com"},
	}
	allow, err := EffectiveAllow(proj, "/tmp/project.yaml")
	if err != nil {
		t.Fatalf("EffectiveAllow: %v", err)
	}
	want := []string{"*.github.com", "corp.example.com", "vpn.example.com", "project.example.com"}
	if !slices.Equal(allow, want) {
		t.Errorf("allow = %v, want %v", allow, want)
	}
	testutil.AssertAllowUnique(t, allow)
}

// TestEffectiveAllowMissingGroupFailsWithProjectPath fails when a selected
// group has no file, naming the project file path in the error.
func TestEffectiveAllowMissingGroupFailsWithProjectPath(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	projectPath, err := CurrentPath()
	if err != nil {
		t.Fatal(err)
	}
	proj := Config{
		Image:       "ghcr.io/woefe/motte/base:latest",
		AllowGroups: []string{"missing-group"},
	}
	_, err = EffectiveAllow(proj, projectPath)
	if err == nil || !strings.Contains(err.Error(), projectPath) || !strings.Contains(err.Error(), "missing-group") {
		t.Fatalf("EffectiveAllow(missing group) = %v, want project path %q and group name", err, projectPath)
	}
}

// TestPolicyGroupValidationErrors covers invalid YAML or rule entries in a
// selected policy group file.
func TestPolicyGroupValidationErrors(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/bad.yaml", "alow:\n  - \"extra.example.com\"\n")
	proj := Config{
		Image:       "ghcr.io/woefe/motte/base:latest",
		AllowGroups: []string{"bad"},
	}
	if _, err := EffectiveAllow(proj, "/tmp/project.yaml"); err == nil || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("error = %v, want unknown-field error naming `alow`", err)
	}

	testutil.WriteConfigFile(t, "policies/bad.yaml", "allow:\n  - \"webserver\"\n")
	if _, err := EffectiveAllow(proj, "/tmp/project.yaml"); err == nil || !strings.Contains(err.Error(), "webserver") {
		t.Fatalf("error = %v, want bad-rule error naming `webserver`", err)
	}
}

// TestFingerprintIncludesImageAndPolicy checks that changing either image or
// network policy changes the fingerprint.
func TestFingerprintIncludesImageAndPolicy(t *testing.T) {
	allow := []string{"dns", "*.github.com"}
	fp1 := Fingerprint("ghcr.io/woefe/motte/base:latest", allow)
	fp2 := Fingerprint("ghcr.io/woefe/motte/golang:latest", allow)
	if fp1 == fp2 {
		t.Error("Fingerprint did not change when image changed")
	}
	fp3 := Fingerprint("ghcr.io/woefe/motte/base:latest", append(slices.Clone(allow), "extra.example.com"))
	if fp1 == fp3 {
		t.Error("Fingerprint did not change when allow list changed")
	}
}

// TestResolveCurrent Resolves the current directory's project, exports secrets
// to host env vars without widening network rules, and hints `motte init` when
// missing.
func TestResolveCurrent(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"EXAMPLE_API_KEY": "sk_test"})
	if _, err := resolveCurrentWithStore(store); err == nil || !strings.Contains(err.Error(), "motte init") {
		t.Fatalf("resolveCurrentWithStore(missing) = %v, want `motte init` hint", err)
	}

	testutil.WriteConfigFile(t, "policies/work.yaml", "allow:\n  - \"dns\"\n")
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow:\n  - \"api.example.com\"\n")
	if _, err := WriteCurrent(Config{
		Image:       "ghcr.io/woefe/motte/base:latest",
		AllowGroups: []string{"work"},
		Secrets:     []string{"EXAMPLE_API_KEY"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("MOTTE_SECRET_EXAMPLE_API_KEY") })

	resolved, err := resolveCurrentWithStore(store)
	if err != nil {
		t.Fatalf("resolveCurrentWithStore: %v", err)
	}
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SandboxName != "motte-"+hash {
		t.Errorf("SandboxName = %q, want %q", resolved.SandboxName, "motte-"+hash)
	}
	if len(resolved.Rules) != 1 {
		t.Errorf("Rules = %+v, want 1 (secret allow host must not widen egress)", resolved.Rules)
	}
	if len(resolved.Secrets) != 1 || resolved.Secrets[0].EnvVar != "EXAMPLE_API_KEY" {
		t.Fatalf("Secrets = %+v", resolved.Secrets)
	}
	if got := os.Getenv("MOTTE_SECRET_EXAMPLE_API_KEY"); got != "sk_test" {
		t.Errorf("MOTTE_SECRET_EXAMPLE_API_KEY = %q, want sk_test", got)
	}
	resolved.ClearSecretEnv()
	if got := os.Getenv("MOTTE_SECRET_EXAMPLE_API_KEY"); got != "" {
		t.Errorf("env still set after ClearSecretEnv: %q", got)
	}

	// Missing secret settings file fails with a hint to run `motte secrets add`.
	if _, err := resolveSecrets([]string{"MISSING_SECRET"}, store); err == nil ||
		!strings.Contains(err.Error(), "motte secrets add") {
		t.Errorf("error = %v, want `motte secrets add` hint", err)
	}

	// Missing keychain value fails with a hint to run `motte secrets set <name>`.
	emptyStore := testutil.NewFakeStore(secrets.ErrNotFound, nil)
	if _, err := resolveSecrets([]string{"EXAMPLE_API_KEY"}, emptyStore); err == nil ||
		!strings.Contains(err.Error(), "motte secrets set EXAMPLE_API_KEY") {
		t.Errorf("error = %v, want `motte secrets set EXAMPLE_API_KEY` hint", err)
	}
}
