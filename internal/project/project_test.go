package project

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
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
	for name, wantImage := range testutil.BuiltinImages() {
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
	if !strings.Contains(string(content), "# motte project\n# Project path: "+dir) {
		t.Errorf("file content = %q, want project path header", string(content))
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
