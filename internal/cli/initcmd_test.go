package cli

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/testutil"
)

// TestInitProjectCreatesAndUpdates covers the interactive `motte init` flow:
// toolchain detection default, opt-out secret selection, re-running with
// pre-filled defaults, and preserving hand-edited `network.allow` entries.
func TestInitProjectCreatesAndUpdates(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", "allow:\n  - \"*.corp.example.com\"\n")
	testutil.WriteConfigFile(t, "secrets/API_KEY_A.yaml", "allow:\n  - \"a.example.com\"\n")
	testutil.WriteConfigFile(t, "secrets/API_KEY_B.yaml", "allow:\n  - \"b.example.com\"\n")

	// First run in a repo with go.mod (-> golang): accept default image
	// (golang), select work-vpn group, accept default secrets (all configured).
	in := bufio.NewReader(strings.NewReader("\nwork-vpn\n\n"))
	if err := initProject(in, io.Discard); err != nil {
		t.Fatalf("initProject(first): %v", err)
	}

	cfg, path, err := project.ReadCurrent()
	if err != nil {
		t.Fatalf("ReadCurrent: %v", err)
	}
	if cfg.Image != "ghcr.io/woefe/motte/golang:latest" {
		t.Errorf("Image = %q, want golang preset image", cfg.Image)
	}
	if !slices.Equal(cfg.AllowGroups, []string{"work-vpn"}) {
		t.Errorf("AllowGroups = %v, want [work-vpn]", cfg.AllowGroups)
	}
	if !slices.Equal(cfg.Secrets, []string{"API_KEY_A", "API_KEY_B"}) {
		t.Errorf("Secrets = %v, want [API_KEY_A API_KEY_B]", cfg.Secrets)
	}

	// Simulate a hand-edit adding network.allow extras.
	cfg.Allow = []string{"*.internal.example.com"}
	if err := project.WriteFile(path, "/workspace", cfg); err != nil {
		t.Fatal(err)
	}

	// Re-run init: switch to web preset, keep groups (press enter), opt out of
	// secrets with "none". Hand-edited Allow must survive.
	in = bufio.NewReader(strings.NewReader("web\n\nnone\n"))
	if err := initProject(in, io.Discard); err != nil {
		t.Fatalf("initProject(rerun): %v", err)
	}
	cfg, _, err = project.ReadCurrent()
	if err != nil {
		t.Fatalf("ReadCurrent(rerun): %v", err)
	}
	if cfg.Image != "ghcr.io/woefe/motte/web:latest" {
		t.Errorf("Image = %q, want web preset image", cfg.Image)
	}
	if !slices.Equal(cfg.Allow, []string{"*.internal.example.com"}) {
		t.Errorf("Allow = %v, want preserved [*.internal.example.com]", cfg.Allow)
	}
	if !slices.Equal(cfg.AllowGroups, []string{"work-vpn"}) {
		t.Errorf("AllowGroups = %v, want kept [work-vpn]", cfg.AllowGroups)
	}
	if len(cfg.Secrets) != 0 {
		t.Errorf("Secrets = %v, want none", cfg.Secrets)
	}
}

// TestInitProjectRejectsUnknownEntities checks that selecting an unknown
// preset, unconfigured group, or unconfigured secret returns a helpful error.
func TestInitProjectRejectsUnknownEntities(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	if err := initProject(bufio.NewReader(strings.NewReader("python\n\n\n")), io.Discard); err == nil ||
		!strings.Contains(err.Error(), "unknown image preset") {
		t.Errorf("error = %v, want unknown image preset error", err)
	}
	if err := initProject(bufio.NewReader(strings.NewReader("base\nmissing-group\n\n")), io.Discard); err == nil ||
		!strings.Contains(err.Error(), "motte policies configure missing-group") {
		t.Errorf("error = %v, want missing policy group error", err)
	}
	if err := initProject(bufio.NewReader(strings.NewReader("base\n\nMISSING_SECRET\n")), io.Discard); err == nil ||
		!strings.Contains(err.Error(), "motte secrets add") {
		t.Errorf("error = %v, want missing secret error", err)
	}
}
