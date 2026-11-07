package cli

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/secrets"
	"github.com/woefe/motte/internal/testutil"
)

// readSpec returns the configured settings of a secret, failing the test
// when its settings file is invalid or missing.
func readSpec(t *testing.T, name string) secrets.Spec {
	t.Helper()
	spec, err := secrets.Read(name)
	if err != nil {
		t.Fatalf("secrets.Read(%s): %v", name, err)
	}
	return spec
}

// TestSecretsLsListsSecrets covers the flat listing: rows aligned by name with
// keychain presence and allowed hosts.
func TestSecretsLsListsSecrets(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"EXAMPLE_API_KEY": "value"})
	testutil.WriteConfigFile(t, "secrets/ANOTHER_KEY.yaml", "allow:\n  - \"a.example.com\"\n  - \"b.example.com\"\n")
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow:\n  - \"*.opencode.ai\"\n")
	var outBuf, errBuf bytes.Buffer
	if err := runSecretsLs(&outBuf, &errBuf, store); err != nil {
		t.Errorf("runSecretsLs: %v", err)
	}
	stdout, stderr := outBuf.String(), errBuf.String()
	want := `ANOTHER_KEY      keychain: no  allow: a.example.com, b.example.com
EXAMPLE_API_KEY  keychain: yes  allow: *.opencode.ai
`
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want none", stderr)
	}
}

// TestSecretsLsEmpty prints the create hint when no secret file exists.
func TestSecretsLsEmpty(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, nil)
	var outBuf, errBuf bytes.Buffer
	if err := runSecretsLs(&outBuf, &errBuf, store); err != nil {
		t.Errorf("runSecretsLs: %v", err)
	}
	stdout, stderr := outBuf.String(), errBuf.String()
	if stdout != "" {
		t.Errorf("stdout = %q, want none", stdout)
	}
	if !strings.Contains(stderr, "no secrets configured") {
		t.Errorf("stderr = %q, want the create hint", stderr)
	}
}

// TestSecretsLsReportsUnreadableSecrets shows a secret file's parse error on
// its row.
func TestSecretsLsReportsUnreadableSecrets(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, nil)
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow: [oops\n")
	var outBuf, errBuf bytes.Buffer
	if err := runSecretsLs(&outBuf, &errBuf, store); err != nil {
		t.Errorf("runSecretsLs: %v", err)
	}
	stdout := outBuf.String()
	if !strings.HasPrefix(stdout, "EXAMPLE_API_KEY  <unreadable: ") {
		t.Errorf("stdout = %q, want the unreadable row", stdout)
	}
}

// TestSecretsConfigureCreatesAndValidates covers the configure command: a
// missing secret file is created from the template and validates afterwards.
func TestSecretsConfigureCreatesAndValidates(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	if err := runSecretsConfigure(io.Discard, "EXAMPLE_API_KEY"); err != nil {
		t.Fatalf("runSecretsConfigure: %v", err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "EXAMPLE_API_KEY.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the secret file: %v", err)
	}
	if !strings.Contains(string(content), "# motte secret — EXAMPLE_API_KEY") {
		t.Errorf("secret file = %q, want the template", string(content))
	}
	if _, err := secrets.Read("EXAMPLE_API_KEY"); err != nil {
		t.Errorf("the template does not validate: %v", err)
	}
}

// TestSecretsConfigureRejectsAnInvalidFile covers the re-validation after the
// editor exits on a pre-existing corrupt file.
func TestSecretsConfigureRejectsAnInvalidFile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.FakeEditor(t)
	testutil.WriteConfigFile(t, "secrets/EXAMPLE_API_KEY.yaml", "allow: [oops\n")
	assertConfigureRejects(t, runSecretsConfigure, "EXAMPLE_API_KEY")
}

// TestSecretsCommandsSurfaceFileErrors covers add, set, and rm against a
// corrupt secret settings file: the real error with the configure hint,
// instead of a masked not-configured error.
func TestSecretsCommandsSurfaceFileErrors(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"API_KEY": "old"})
	testutil.WriteConfigFile(t, "secrets/API_KEY.yaml", "allow: [oops\n")
	commands := []struct {
		name string
		run  func() error
	}{
		{name: "add", run: func() error {
			in := bufio.NewReader(strings.NewReader("API_KEY\n"))
			return addSecret(in, strings.NewReader(""), io.Discard, store)
		}},
		{name: "set", run: func() error {
			return runSecretsSet(strings.NewReader(""), io.Discard, store, "API_KEY")
		}},
		{name: "rm", run: func() error {
			return runSecretsRm(strings.NewReader(""), io.Discard, store, "API_KEY", true)
		}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			err := command.run()
			if err == nil || !strings.Contains(err.Error(), "invalid secret config") ||
				!strings.Contains(err.Error(), "motte secrets configure API_KEY") {
				t.Errorf("error = %v, want the invalid-config error with the configure hint", err)
			}
		})
	}

	// Missing secret file: set points at add, rm does not.
	if err := runSecretsSet(strings.NewReader(""), io.Discard, store, "MISSING_KEY"); err == nil ||
		!strings.Contains(err.Error(), "motte secrets add") {
		t.Errorf("set error = %v, want the add hint", err)
	}
	if err := runSecretsRm(strings.NewReader(""), io.Discard, store, "MISSING_KEY", true); err == nil ||
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
	testutil.WriteConfigFile(t, "secrets/FOO.yaml", "allow:\n  - \"*.foo.example.com\"\n")
	store := testutil.NewFakeStore(secrets.ErrNotFound, map[string]string{"FOO": "current"})

	err := addSecret(
		bufio.NewReader(strings.NewReader("BAR\n*.bar.example.com\n")),
		strings.NewReader("bar-value\n"),
		io.Discard,
		store,
	)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["BAR"] != "bar-value" {
		t.Errorf("keychain BAR = %q, want bar-value", store.Items["BAR"])
	}
	if spec := readSpec(t, "BAR"); spec.Allow[0] != "*.bar.example.com" {
		t.Errorf("BAR allow = %v, want the entered hosts", spec.Allow)
	}

	// Settings-only change: the prefilled default is accepted, the value
	// prompt is skipped, the keychain value stays.
	err = addSecret(bufio.NewReader(strings.NewReader("FOO\n\nn\n")), strings.NewReader(""), io.Discard, store)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["FOO"] != "current" {
		t.Errorf("keychain FOO = %q, want the kept value", store.Items["FOO"])
	}
	if spec := readSpec(t, "FOO"); spec.Allow[0] != "*.foo.example.com" {
		t.Errorf("FOO allow = %v, want the prefilled default", spec.Allow)
	}

	// Value replaced on request, hosts changed with it.
	err = addSecret(
		bufio.NewReader(strings.NewReader("FOO\n*.new.example.com\ny\n")),
		strings.NewReader("new-value\n"),
		io.Discard,
		store,
	)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if store.Items["FOO"] != "new-value" {
		t.Errorf("keychain FOO = %q, want new-value", store.Items["FOO"])
	}
	if spec := readSpec(t, "FOO"); spec.Allow[0] != "*.new.example.com" {
		t.Errorf("FOO allow = %v, want the new hosts", spec.Allow)
	}

	// A configured secret without a keychain value prompts for one.
	empty := testutil.NewFakeStore(secrets.ErrNotFound, nil)
	err = addSecret(bufio.NewReader(strings.NewReader("FOO\n\n")), strings.NewReader("restored\n"), io.Discard, empty)
	if err != nil {
		t.Fatalf("addSecret: %v", err)
	}
	if empty.Items["FOO"] != "restored" {
		t.Errorf("keychain FOO = %q, want restored", empty.Items["FOO"])
	}
	if spec := readSpec(t, "FOO"); spec.Allow[0] != "*.new.example.com" {
		t.Errorf("FOO allow = %v, want the kept hosts", spec.Allow)
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
		t.Errorf("readSecretValue(empty) = %q %v, want empty", value, err)
	}
}
