package launcher

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// TestLoadProjectMissingHintsInit checks that booting without a project config
// fails with a hint to run `motte init`.
func TestLoadProjectMissingHintsInit(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	_, _, err := loadProject()
	if err == nil || !strings.Contains(err.Error(), "motte init") {
		t.Fatalf("loadProject(missing) = %v, want `motte init` hint", err)
	}
}

// TestSandboxName checks that the sandbox name is `motte-<dir-hash>`.
func TestSandboxName(t *testing.T) {
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	name, err := sandboxName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "motte-"+hash {
		t.Errorf("sandboxName() = %q, want %q", name, "motte-"+hash)
	}
}

// TestEffectiveAllowExtendsAndDedups merges selected policy groups and
// project allow entries in order, deduplicating.
func TestEffectiveAllowExtendsAndDedups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "policies/corp.yaml", "allow:\n  - \"*.github.com\"\n  - \"corp.example.com\"\n")
	testutil.WriteConfigFile(t, "policies/vpn.yaml", "allow:\n  - \"corp.example.com\"\n  - \"vpn.example.com\"\n")

	proj := project.Config{
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
	projectPath, err := project.CurrentPath()
	if err != nil {
		t.Fatal(err)
	}
	proj := project.Config{
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
	proj := project.Config{
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

// TestResolveSecrets checks that selected secrets resolve from settings files
// and the keychain into host env vars, do not widen egress, and fail with
// clear hints when settings or keychain values are missing.
func TestResolveSecrets(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"EXAMPLE_API_KEY": "sk_test"})
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow:\n  - \"api.example.com\"\n")
	t.Cleanup(func() { _ = os.Unsetenv("MOTTE_SECRET_EXAMPLE_API_KEY") })

	allow, err := EffectiveAllow(project.Config{Image: "ghcr.io/woefe/motte/base:latest"}, "/tmp/project.yaml")
	if err != nil {
		t.Fatalf("EffectiveAllow: %v", err)
	}
	resolved, err := resolveSecrets([]string{"EXAMPLE_API_KEY"}, store)
	if err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	if len(resolved) != 1 || resolved[0].Name != "EXAMPLE_API_KEY" {
		t.Fatalf("resolveSecrets = %+v", resolved)
	}
	if got := os.Getenv("MOTTE_SECRET_EXAMPLE_API_KEY"); got != "sk_test" {
		t.Errorf("MOTTE_SECRET_EXAMPLE_API_KEY = %q", got)
	}
	// Secret allow hosts must NOT automatically widen the egress allow list.
	if slices.Contains(allow, "api.example.com") {
		t.Errorf("allow unexpectedly contains secret host api.example.com: %v", allow)
	}
	unsetSecretEnv(resolved)
	if got := os.Getenv("MOTTE_SECRET_EXAMPLE_API_KEY"); got != "" {
		t.Errorf("env still set after unsetting: %q", got)
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

// TestLogCreationProgress logs each stage once despite repeated events, and
// closes the returned channel after the event stream drains.
func TestLogCreationProgress(t *testing.T) {
	events := make(chan m.CreationProgress, 8)
	for _, kind := range []string{"pull", "pull", "startup", "startup"} {
		events <- m.CreationProgress{Kind: kind}
	}
	close(events)

	buf := testutil.SwapLogger(t)
	done := logCreationProgress(events)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done did not close after the event stream drained")
	}
	for _, msg := range []string{"pulling image", "booting sandbox"} {
		if got := strings.Count(buf.String(), msg); got != 1 {
			t.Errorf("%q logged %d times, want once; log: %s", msg, got, buf.String())
		}
	}
}

// TestLogCreationProgressSkipsUnknownKinds: unknown kinds log nothing but
// still drain and close the channel.
func TestLogCreationProgressSkipsUnknownKinds(t *testing.T) {
	events := make(chan m.CreationProgress, 2)
	events <- m.CreationProgress{Kind: "layer"}
	close(events)

	buf := testutil.SwapLogger(t)
	done := logCreationProgress(events)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done did not close after the event stream drained")
	}
	if got := buf.String(); got != "" {
		t.Errorf("log for unknown events = %q, want empty", got)
	}
}
