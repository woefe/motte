// Shared helpers for the package tests: isolated config trees, output
// capture, testdata fixtures, and the assertion helpers and fakes used
// across packages. The package imports no motte package so every package's
// tests can use it without import cycles; motte-specific inputs (such as the
// not-found sentinel of FakeStore) are passed in by the caller.
package testutil

import (
	"bytes"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

// IsolatedConfigDir points XDG_CONFIG_HOME at a fresh temp dir so tests never
// read a real ~/.config/motte.
func IsolatedConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// Fixture returns the contents of a testdata file of the calling package
// (relpath uses /).
func Fixture(t *testing.T, relpath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", relpath))
	if err != nil {
		t.Fatalf("read fixture %s: %v", relpath, err)
	}
	return string(data)
}

// WriteConfigFile writes a file under $XDG_CONFIG_HOME/motte (relpath uses /).
func WriteConfigFile(t *testing.T, relpath, content string) {
	t.Helper()
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", relpath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// FakeEditor makes the configure flow's editor step succeed without changing
// the file it opens.
func FakeEditor(t *testing.T) {
	t.Helper()
	t.Setenv("VISUAL", "true")
	t.Setenv("EDITOR", "true")
}

// SwapLogger replaces the default slog logger with one writing to the
// returned buffer, restoring the previous logger at cleanup.
func SwapLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := new(bytes.Buffer)
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	return buf
}

// AssertAllowListed fails unless each target appears in the allow list.
func AssertAllowListed(t *testing.T, allow []string, targets ...string) {
	t.Helper()
	for _, target := range targets {
		if slices.Contains(allow, target) {
			continue
		}
		t.Errorf("allow list misses %q; got %v", target, allow)
	}
}

// AssertAllowUnique fails when the allow list repeats an entry.
func AssertAllowUnique(t *testing.T, allow []string) {
	t.Helper()
	seen := make(map[string]bool, len(allow))
	for _, entry := range allow {
		if seen[entry] {
			t.Errorf("allow has duplicate %q", entry)
		}
		seen[entry] = true
	}
}

// DNSRule is the expansion every plain dns entry shares.
var DNSRule = msb.PolicyRule{
	Action:      msb.PolicyActionAllow,
	Direction:   msb.PolicyDirectionEgress,
	Destination: "host",
	Protocols:   []msb.PolicyProtocol{msb.PolicyProtocolUDP, msb.PolicyProtocolTCP},
	Port:        "53",
}

// AssertRule compares policy rules field by field; PolicyRule holds slices
// and is not comparable with ==.
func AssertRule(t *testing.T, got, want msb.PolicyRule) {
	t.Helper()
	if got.Action != want.Action || got.Direction != want.Direction || got.Destination != want.Destination {
		t.Errorf("rule = {action %v, direction %v, destination %q}, want {%v %v %q}",
			got.Action, got.Direction, got.Destination, want.Action, want.Direction, want.Destination)
	}
	if len(got.Protocols) != len(want.Protocols) {
		t.Fatalf("protocols = %v, want %v", got.Protocols, want.Protocols)
	}
	for i := range want.Protocols {
		if got.Protocols[i] != want.Protocols[i] {
			t.Errorf("protocols = %v, want %v", got.Protocols, want.Protocols)
		}
	}
	if got.Port != want.Port || len(got.Ports) != len(want.Ports) {
		t.Errorf("ports = {port %q, ports %v}, want {%q %v}", got.Port, got.Ports, want.Port, want.Ports)
	}
}

// FakeStore is an in-memory keychain stand-in implementing the secrets
// store interface. Missing accounts fail with NotFound wrapped, so callers
// pass their package's not-found sentinel.
type FakeStore struct {
	Items    map[string]string
	NotFound error
}

// NewFakeStore returns a FakeStore holding a copy of values.
func NewFakeStore(notFound error, values map[string]string) *FakeStore {
	items := make(map[string]string, len(values))
	maps.Copy(items, values)
	return &FakeStore{Items: items, NotFound: notFound}
}

// Get returns the stored value of an account.
func (f *FakeStore) Get(account string) (string, error) {
	if value, ok := f.Items[account]; ok {
		return value, nil
	}
	return "", fmt.Errorf("secret %s: %w", account, f.NotFound)
}

// Set stores an account's value.
func (f *FakeStore) Set(account, value string) error {
	f.Items[account] = value
	return nil
}

// Delete drops an account.
func (f *FakeStore) Delete(account string) error {
	delete(f.Items, account)
	return nil
}
