package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// swapStore replaces the default keychain store, restoring it at cleanup.
func swapStore(t *testing.T, store secrets.Store) {
	t.Helper()
	original := secrets.DefaultStore
	secrets.DefaultStore = store
	t.Cleanup(func() { secrets.DefaultStore = original })
}

// readSpec returns the configured settings of a secret, failing the test
// when its scope file is invalid or the secret is missing.
func readSpec(t *testing.T, n secrets.Name) secrets.Spec {
	t.Helper()
	configured, err := secrets.ReadScope(secrets.ScopeKeyOf(n))
	if err != nil {
		t.Fatalf("ReadScope(%s): %v", n.Full, err)
	}
	spec, ok := configured[n.Leaf]
	if !ok {
		t.Fatalf("secret %s is not configured", n.Full)
	}
	return spec
}

// TestSecretsLsListsGroups covers the grouped listing: rows aligned by name,
// the current-directory mark, placeholder bodies, and the shadowing note.
func TestSecretsLsListsGroups(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"EXAMPLE_API_KEY": "value"}))
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteConfigFile(t, "secrets/global.yaml", testutil.Fixture(t, "secrets/ls/global.yaml"))
	testutil.WriteConfigFile(t, "secrets/golang.yaml", "secrets:\n")
	testutil.WriteConfigFile(t, "secrets/"+hash+".yaml", testutil.Fixture(t, "secrets/ls/project.yaml"))
	stdout, stderr := testutil.CaptureOutput(t, func() {
		if err := runSecretsLs(); err != nil {
			t.Errorf("runSecretsLs: %v", err)
		}
	})
	want := fmt.Sprintf(`global:
  ANOTHER_KEY      keychain: no  allow: a.example.com, b.example.com
  EXAMPLE_API_KEY  keychain: yes  allow: *.opencode.ai

profile golang:
  (no secrets)

project %s (this directory):
  %s/EXAMPLE_API_KEY  keychain: no  allow: project.example.com

note: EXAMPLE_API_KEY is configured in 2 scopes; the most specific wins
`, hash, hash)
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want none", stderr)
	}
}

// TestSecretsLsEmpty prints the create hint when no scope file exists.
func TestSecretsLsEmpty(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, nil))
	stdout, stderr := testutil.CaptureOutput(t, func() {
		if err := runSecretsLs(); err != nil {
			t.Errorf("runSecretsLs: %v", err)
		}
	})
	if stdout != "" {
		t.Errorf("stdout = %q, want none", stdout)
	}
	if !strings.Contains(stderr, "no secrets configured") {
		t.Errorf("stderr = %q, want the create hint", stderr)
	}
}

// TestSecretsLsReportsUnreadableScopes shows a scope's parse error under its
// group header.
func TestSecretsLsReportsUnreadableScopes(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, nil))
	testutil.WriteConfigFile(t, "secrets/global.yaml", "secrets: [oops\n")
	stdout, _ := testutil.CaptureOutput(t, func() {
		if err := runSecretsLs(); err != nil {
			t.Errorf("runSecretsLs: %v", err)
		}
	})
	if !strings.HasPrefix(stdout, "global:\n  <unreadable: ") {
		t.Errorf("stdout = %q, want the unreadable group", stdout)
	}
}

// TestSecretsConfigureCreatesAndValidates covers the configure command: a
// missing scope file is created from the template and validates, and the
// project scope gets a file of its own.
func TestSecretsConfigureCreatesAndValidates(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	if err := runSecretsConfigure("global"); err != nil {
		t.Fatalf("runSecretsConfigure: %v", err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "global.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the scope file: %v", err)
	}
	if !strings.Contains(string(content), "secrets:") {
		t.Errorf("scope file = %q, want the template", string(content))
	}
	if _, err := secrets.ReadScope(secrets.ScopeKey{Scope: secrets.ScopeGlobal}); err != nil {
		t.Errorf("the template does not validate: %v", err)
	}

	if err := runSecretsConfigure("project"); err != nil {
		t.Fatalf("runSecretsConfigure(project): %v", err)
	}
	key := secrets.ScopeKey{Scope: secrets.ScopeProject, Hash: mustDirHash(t)}
	projectFile, err := key.Path()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(projectFile); err != nil {
		t.Fatalf("reading the project scope file: %v", err)
	}
}

// TestSecretsConfigureRejectsAnInvalidFile covers the re-validation after the
// editor exits on a pre-existing corrupt file.
func TestSecretsConfigureRejectsAnInvalidFile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	testutil.WriteConfigFile(t, "secrets/global.yaml", "secrets:\n  KEY: [oops\n")
	assertConfigureRejects(t, runSecretsConfigure)
}

// TestSecretsCommandsSurfaceScopeFileErrors covers add, set, and rm against a
// corrupt scope file: the real error with the configure hint, instead of a
// masked not-configured error.
func TestSecretsCommandsSurfaceScopeFileErrors(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"golang/API_KEY": "old"}))
	testutil.WriteConfigFile(t, "secrets/golang.yaml", "secrets:\n  API_KEY: [oops\n")
	commands := []struct {
		name string
		run  func() error
	}{
		{name: "add", run: func() error {
			return addSecret(bufio.NewReader(strings.NewReader("API_KEY\np\ngolang\n")), strings.NewReader(""))
		}},
		{name: "set", run: func() error { return runSecretsSet("golang/API_KEY") }},
		{name: "rm", run: func() error { return runSecretsRm("golang/API_KEY", true) }},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			err := command.run()
			if err == nil || !strings.Contains(err.Error(), "invalid secret config") ||
				!strings.Contains(err.Error(), "motte secrets configure golang") {
				t.Errorf("error = %v, want the invalid-config error with the configure hint", err)
			}
		})
	}

	// A healthy scope without the secret: set points at add, rm does not.
	testutil.WriteConfigFile(t, "secrets/golang.yaml", "secrets:\n  OTHER:\n    allow: [\"*.example.com\"]\n")
	if err := runSecretsSet("golang/API_KEY"); err == nil ||
		!strings.Contains(err.Error(), "motte secrets add") {
		t.Errorf("set error = %v, want the add hint", err)
	}
	if err := runSecretsRm("golang/API_KEY", true); err == nil ||
		strings.Contains(err.Error(), "add") {
		t.Errorf("rm error = %v, want no create hint", err)
	}
}

// TestAddSecretUpsert covers the interactive flow: a fresh secret stores its
// value and settings, a configured one pre-fills its settings and replaces the
// keychain value only on request, and a configured one without a keychain
// value prompts for it.
func TestAddSecretUpsert(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "secrets/global.yaml",
		"secrets:\n  FOO:\n    allow:\n      - \"*.foo.example.com\"\n")
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"FOO": "current"})
	swapStore(t, store)

	err := addSecret(
		bufio.NewReader(strings.NewReader("BAR\n\n*.bar.example.com\n")),
		strings.NewReader("bar-value\n"),
	)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["BAR"] != "bar-value" {
		t.Errorf("keychain BAR = %q, want bar-value", store.Items["BAR"])
	}
	bar, err := secrets.ParseName("BAR")
	if err != nil {
		t.Fatal(err)
	}
	if spec := readSpec(t, bar); spec.Allow[0] != "*.bar.example.com" {
		t.Errorf("BAR allow = %v, want the entered hosts", spec.Allow)
	}

	// Settings-only change: the prefilled default is accepted, the value
	// prompt is skipped, the keychain value stays.
	foo, err := secrets.ParseName("FOO")
	if err != nil {
		t.Fatal(err)
	}
	err = addSecret(bufio.NewReader(strings.NewReader("FOO\n\n\nn\n")), strings.NewReader(""))
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["FOO"] != "current" {
		t.Errorf("keychain FOO = %q, want the kept value", store.Items["FOO"])
	}
	if spec := readSpec(t, foo); spec.Allow[0] != "*.foo.example.com" {
		t.Errorf("FOO allow = %v, want the prefilled default", spec.Allow)
	}

	// Value replaced on request, hosts changed with it.
	err = addSecret(
		bufio.NewReader(strings.NewReader("FOO\n\n*.new.example.com\ny\n")),
		strings.NewReader("new-value\n"),
	)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["FOO"] != "new-value" {
		t.Errorf("keychain FOO = %q, want new-value", store.Items["FOO"])
	}
	if spec := readSpec(t, foo); spec.Allow[0] != "*.new.example.com" {
		t.Errorf("FOO allow = %v, want the new hosts", spec.Allow)
	}

	// A configured secret without a keychain value prompts for one.
	empty := testutil.NewFakeStore(secrets.ErrNotFound, nil)
	swapStore(t, empty)
	err = addSecret(bufio.NewReader(strings.NewReader("FOO\n\n\n")), strings.NewReader("restored\n"))
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if empty.Items["FOO"] != "restored" {
		t.Errorf("keychain FOO = %q, want restored", empty.Items["FOO"])
	}
	if spec := readSpec(t, foo); spec.Allow[0] != "*.new.example.com" {
		t.Errorf("FOO allow = %v, want the kept hosts", spec.Allow)
	}
}

// TestAddSecretOnAnEmptyScopeTemplate covers the first add on a scope file
// that configure created from the template: its null `secrets:` widens into
// a mapping, and the template's comments survive.
func TestAddSecretOnAnEmptyScopeTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	key := secrets.ScopeKey{Scope: secrets.ScopeGlobal}
	path, err := key.Path()
	if err != nil {
		t.Fatal(err)
	}
	template, err := secrets.Template(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WriteNewFile(path, template); err != nil {
		t.Fatalf("WriteNewFile: %v", err)
	}
	swapStore(t, testutil.NewFakeStore(secrets.ErrNotFound, nil))
	err = addSecret(
		bufio.NewReader(strings.NewReader("BAR\n\n*.bar.example.com\n")),
		strings.NewReader("bar-value\n"),
	)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	name, err := secrets.ParseName("BAR")
	if err != nil {
		t.Fatal(err)
	}
	if spec := readSpec(t, name); spec.Allow[0] != "*.bar.example.com" {
		t.Errorf("BAR allow = %v, want the entered hosts", spec.Allow)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "# Values live in the OS keychain") ||
		!strings.Contains(string(content), "# EXAMPLE_API_KEY:") {
		t.Errorf("scope file = %q, want the template comments", string(content))
	}
}

// TestReadSecretValue covers the piped non-TTY value reader: no echo prompt,
// one line only, trailing newline trimmed.
func TestReadSecretValue(t *testing.T) {
	value, err := readSecretValue("value (input hidden): ", io.Discard, strings.NewReader("sk_test\n"))
	if err != nil || value != "sk_test" {
		t.Errorf("readSecretValue = %q %v, want sk_test", value, err)
	}
	if _, err := readSecretValue("value: ", io.Discard, strings.NewReader("a\nb\n")); err == nil ||
		!strings.Contains(err.Error(), "single line") {
		t.Errorf("error = %v, want a single-line restriction", err)
	}
	if value, err := readSecretValue("value: ", io.Discard, strings.NewReader("")); err != nil || value != "" {
		t.Errorf("readSecretValue(empty) = %q %v", value, err)
	}
}
