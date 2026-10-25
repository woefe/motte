package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeStore is an in-memory secretStore standing in for the OS keychain.
type fakeStore struct{ items map[string]string }

func newFakeStore(values map[string]string) *fakeStore {
	items := make(map[string]string, len(values))
	for account, value := range values {
		items[account] = value
	}
	return &fakeStore{items: items}
}

func (f *fakeStore) get(account string) (string, error) {
	if value, ok := f.items[account]; ok {
		return value, nil
	}
	return "", fmt.Errorf("secret %s: %w", account, errSecretNotFound)
}

func (f *fakeStore) set(account, value string) error {
	f.items[account] = value
	return nil
}

func (f *fakeStore) delete(account string) error { delete(f.items, account); return nil }

// swapStore replaces the default keychain store, restoring it at cleanup.
func swapStore(t *testing.T, store secretStore) {
	t.Helper()
	original := defaultSecretStore
	defaultSecretStore = store
	t.Cleanup(func() { defaultSecretStore = original })
}

// writeSecretFS writes a file under $XDG_CONFIG_HOME/motte (relpath uses /).
func writeSecretFS(t *testing.T, relpath, content string) {
	t.Helper()
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", relpath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestParseSecretName covers the path-like name grammar per scope.
func TestParseSecretName(t *testing.T) {
	tests := []struct {
		name        string
		wantScope   secretScope
		wantProfile string
		wantLeaf    string
		wantErr     string
	}{
		{name: "OPENCODE_GO_KEY", wantScope: scopeGlobal, wantLeaf: "OPENCODE_GO_KEY"},
		{name: "golang/OPENCODE_GO_KEY", wantScope: scopeProfile, wantProfile: "golang", wantLeaf: "OPENCODE_GO_KEY"},
		{name: "web/login_token", wantScope: scopeProfile, wantProfile: "web", wantLeaf: "login_token"},
		{name: "golang/1234567890ab/FOO", wantScope: scopeProject, wantProfile: "golang", wantLeaf: "FOO"},
		{name: "", wantErr: "empty secret name"},
		{name: "golang//FOO", wantErr: "invalid secret name"},
		{name: "a/b/c/d", wantErr: "at most three segments"},
		{name: "rails/FOO", wantErr: "not a built-in profile"},
		{name: "webserver/FOO", wantErr: "not a built-in profile"},
		{name: "web/12345/FOO", wantErr: "project hash"},
		{name: "golang/1234567890AB/FOO", wantErr: "project hash"},
		{name: "FOO-BAR", wantErr: "valid env var"},
		{name: "web/FOO.BAR", wantErr: "valid env var"},
		{name: "1234567890ab/FOO", wantErr: "not a built-in profile"},
		{name: "FOO$BAR", wantErr: "valid env var"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseSecretName(test.name)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("parseSecretName(%q) error = %v, want containing %q", test.name, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSecretName(%q): %v", test.name, err)
			}
			if got.scope != test.wantScope || got.profile != test.wantProfile || got.leaf != test.wantLeaf {
				t.Errorf("parseSecretName(%q) = %+v, want scope/profile/leaf %d/%q/%q",
					test.name, got, test.wantScope, test.wantProfile, test.wantLeaf)
			}
		})
	}
}

// TestValidateSecretAllowEntry covers the host-pattern grammar of secret
// allow lists (exact hosts, *.suffix wildcards, and `*`).
func TestValidateSecretAllowEntry(t *testing.T) {
	for _, ok := range []string{"*", "api.example.com", "*.example.com", "a.b.c.d"} {
		if err := validateSecretAllowEntry(ok); err != nil {
			t.Errorf("validateSecretAllowEntry(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "webserver", "localhost", "*.example.com:443", "host:tcp:9931", "*. *", "ex ample.com"} {
		if err := validateSecretAllowEntry(bad); err == nil {
			t.Errorf("validateSecretAllowEntry(%q) = nil, want an error", bad)
		}
	}
}

// TestReadWriteSecretMeta round-trips a config file and covers schema
// strictness: unknown fields fail, allow is required, header fields default.
func TestReadWriteSecretMeta(t *testing.T) {
	isolatedConfigDir(t)
	name, err := parseSecretName("golang/OPENCODE_GO_KEY")
	if err != nil {
		t.Fatal(err)
	}
	spec := secretSpec{allow: []string{"*.opencode.ai"}, headerFields: []string{"authorization"}}
	if err := writeSecretMeta(name, spec); err != nil {
		t.Fatalf("writeSecretMeta: %v", err)
	}
	got, err := readSecretMeta(name)
	if err != nil {
		t.Fatalf("readSecretMeta: %v", err)
	}
	if got.name != "golang/OPENCODE_GO_KEY" || got.envVar != "OPENCODE_GO_KEY" ||
		len(got.allow) != 1 || got.allow[0] != "*.opencode.ai" ||
		len(got.headerFields) != 1 || got.headerFields[0] != "authorization" {
		t.Fatalf("readSecretMeta = %+v", got)
	}

	// Unknown fields fail lint-style, with the path in the error.
	writeSecretFS(t, "secrets/golang/OPENCODE_GO_KEY.yaml", "allow: [\"api.example.com\"]\nalow: [oops]\n")
	_, err = readSecretMeta(name)
	if err == nil || !strings.Contains(err.Error(), "invalid secret config") || !strings.Contains(err.Error(), "alow") {
		t.Errorf("error = %v, want an unknown-field error naming alow", err)
	}

	// A missing allow list is invalid.
	writeSecretFS(t, "secrets/golang/OPENCODE_GO_KEY.yaml", "header_fields: [origin]\n")
	if _, err := readSecretMeta(name); !strings.Contains(err.Error(), "allow is empty") {
		t.Errorf("error = %v, want an empty-allow error", err)
	}

	// Allow hosts must be host patterns, not network rule targets.
	writeSecretFS(t, "secrets/golang/OPENCODE_GO_KEY.yaml", "allow: [\"host:tcp:9931\"]\n")
	if _, err := readSecretMeta(name); err == nil || !strings.Contains(err.Error(), "invalid secret allow host") {
		t.Errorf("error = %v, want a bad-host error", err)
	}
}

// TestScanEffectiveSecretsPrecedence resolves global, profile, and project
// scopes with project > profile > global, deduping by env var name.
func TestScanEffectiveSecretsPrecedence(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	secretDoc := func(allow string) string {
		return "allow:\n  - \"" + allow + "\"\n"
	}
	writeSecretFS(t, "secrets/OPENCODE_GO_KEY.yaml", secretDoc("global.example.com"))
	writeSecretFS(t, "secrets/golang/OPENCODE_GO_KEY.yaml", secretDoc("profile.example.com"))
	writeSecretFS(t, "secrets/golang/"+hash+"/OPENCODE_GO_KEY.yaml", secretDoc("project.example.com"))
	writeSecretFS(t, "secrets/golang/OTHER_SECRET.yaml", secretDoc("other.example.com"))

	effective, err := scanEffectiveSecrets("golang")
	if err != nil {
		t.Fatalf("scanEffectiveSecrets: %v", err)
	}
	if len(effective) != 2 {
		t.Fatalf("effective = %+v, want 2 secrets", effective)
	}
	if effective[0].envVar != "OPENCODE_GO_KEY" || effective[0].allow[0] != "project.example.com" {
		t.Errorf("OPENCODE_GO_KEY = %+v, want allow project.example.com", effective[0])
	}
	if effective[1].envVar != "OTHER_SECRET" || effective[1].allow[0] != "other.example.com" {
		t.Errorf("OTHER_SECRET = %+v, want other.example.com", effective[1])
	}

	// Another profile sees only the global scope: other profiles' secrets
	// never leak into its launch.
	effective, err = scanEffectiveSecrets("web")
	if err != nil {
		t.Fatalf("scanEffectiveSecrets(web): %v", err)
	}
	if len(effective) != 1 || effective[0].allow[0] != "global.example.com" {
		t.Fatalf("web effective = %+v, want only the global secret", effective)
	}
}

// TestResolveSecrets: values come from the keychain into host env vars, egress
// extends with the secrets' allow entries, and a keychain-less secret fails
// the launch with the set hint.
func TestResolveSecrets(t *testing.T) {
	isolatedConfigDir(t)
	swapStore(t, newFakeStore(map[string]string{"OPENCODE_GO_KEY": "sk_test"}))
	writeSecretFS(t, "secrets/OPENCODE_GO_KEY.yaml", "allow:\n  - \"*.opencode.ai\"\n")
	t.Cleanup(func() { _ = os.Unsetenv("MOTTE_SECRET_OPENCODE_GO_KEY") })

	profile, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	secrets, err := resolveSecrets(profile)
	if err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].name != "OPENCODE_GO_KEY" {
		t.Fatalf("resolveSecrets = %+v", secrets)
	}
	if got := os.Getenv("MOTTE_SECRET_OPENCODE_GO_KEY"); got != "sk_test" {
		t.Errorf("MOTTE_SECRET_OPENCODE_GO_KEY = %q", got)
	}
	// Egress auto-extends with the secrets' allow entries.
	if !sliceContains(*profile.network.Allow, "*.opencode.ai") {
		t.Errorf("allow misses the secret's host: %v", *profile.network.Allow)
	}
	unsetSecretEnv(secrets)
	if got := os.Getenv("MOTTE_SECRET_OPENCODE_GO_KEY"); got != "" {
		t.Errorf("env still set after unsetting: %q", got)
	}

	// Without a keychain value the launch fails with a set hint.
	swapStore(t, newFakeStore(nil))
	if _, err := resolveSecrets(profile); err == nil ||
		!strings.Contains(err.Error(), "motte secrets set OPENCODE_GO_KEY") {
		t.Errorf("error = %v, want the set hint", err)
	}
}

// TestParseStoredSecrets covers the durable config shapes: array or map,
// HostPattern objects or strings, and the injection alias.
func TestParseStoredSecrets(t *testing.T) {
	arrayShape := `{"network":{"secrets":{"secrets":[
		{"env_var":"OPENCODE_GO_KEY","value":"","source":{"kind":"env","var":"MOTTE_SECRET_OPENCODE_GO_KEY"},
		 "allowed_hosts":[{"wildcard":"*.opencode.ai"},{"exact":"api.example.com"}],
		 "substitution":{"headers":true,"header_fields":["authorization"]}},
		{"env_var":"legacy","value":"plaintext","allowed_hosts":["legacy.example.com"],
		 "injection":{"header_fields":["origin"]}}]}}}`
	stored, err := parseStoredSecrets(arrayShape)
	if err != nil {
		t.Fatalf("parseStoredSecrets: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored = %+v, want 2", stored)
	}
	first := stored[0]
	if first.envVar != "OPENCODE_GO_KEY" || first.value != "" ||
		len(first.allow) != 2 || first.allow[0] != "*.opencode.ai" || first.allow[1] != "api.example.com" ||
		len(first.headerFields) != 1 || first.headerFields[0] != "authorization" {
		t.Errorf("first = %+v", first)
	}
	if second := stored[1]; second.envVar != "legacy" || second.value != "plaintext" ||
		len(second.allow) != 1 || second.allow[0] != "legacy.example.com" ||
		len(second.headerFields) != 1 || second.headerFields[0] != "origin" {
		t.Errorf("second = %+v", second)
	}

	mapShape := `{"network":{"secrets":{"secrets":{"open_key":
		{"env_var":"OPEN_KEY","value":"","allowed_hosts":[{"exact":"ok.example.com"}]}}}}}`
	stored, err = parseStoredSecrets(mapShape)
	if err != nil {
		t.Fatalf("parseStoredSecrets(map): %v", err)
	}
	if len(stored) != 1 || stored[0].envVar != "OPEN_KEY" || stored[0].allow[0] != "ok.example.com" {
		t.Fatalf("map stored = %+v", stored)
	}

	// No secrets section, no entries.
	if stored, err := parseStoredSecrets(`{"network":{}}`); err != nil || stored != nil {
		t.Fatalf("empty config = %v %v", stored, err)
	}
}

// TestSecretDrift compares stored against desired: adds, raw migrations,
// host-policy changes, and removals.
func TestSecretDrift(t *testing.T) {
	desired := []secretSpec{
		{envVar: "a_key", allow: []string{"a.example.com"}, headerFields: []string{"authorization"}},
		{envVar: "b_key", allow: []string{"b.example.com"}, headerFields: []string{"authorization"}},
	}

	// Nothing stored: everything is an add.
	upsert, remove, migrated := secretDrift(nil, desired)
	if len(upsert) != 2 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("nil stored: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Matching env-source stored secrets: no drift.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{envVar: "a_key", allow: []string{"a.example.com"}, headerFields: []string{"authorization"}},
		{envVar: "b_key", allow: []string{"b.example.com"}, headerFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 0 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("matching: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Raw plaintext stored value: migrates to an env reference; the desired
	// b_key is not stored, so it is added in the same patch.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{
			envVar:       "a_key",
			value:        "plaintext",
			allow:        []string{"a.example.com"},
			headerFields: []string{"authorization"},
		},
	}, desired)
	if len(upsert) != 2 || upsert[0].envVar != "a_key" || upsert[1].envVar != "b_key" ||
		len(migrated) != 1 || migrated[0] != "a_key" || len(remove) != 0 {
		t.Fatalf("raw: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// A host mismatch changes the stored rule; b_key is additionally added.
	upsert, remove, migrated = secretDrift([]storedSecret{
		{envVar: "a_key", allow: []string{"other.example.com"}, headerFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 2 || upsert[0].envVar != "a_key" || len(migrated) != 0 {
		t.Fatalf("host mismatch: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Stored secrets not desired are removed.
	upsert, remove, migrated = secretDrift([]storedSecret{{envVar: "stale_key"}}, nil)
	if len(upsert) != 0 || len(remove) != 1 || remove[0] != "stale_key" || len(migrated) != 0 {
		t.Fatalf("stale: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}
}

// TestSecretModifySpecs builds modify entries with env references only.
func TestSecretModifySpecs(t *testing.T) {
	specs := secretModifySpecs([]secretSpec{
		{envVar: "a_key", allow: []string{"a.example.com"}, headerFields: []string{"authorization"}},
	})
	spec, ok := specs["a_key"]
	if !ok {
		t.Fatalf("specs = %+v, want a_key", specs)
	}
	if spec.Env != "MOTTE_SECRET_a_key" || spec.Value != "" || spec.Store != "" {
		t.Errorf("spec = %+v, want env-only material", spec)
	}
	if len(spec.AllowedHosts) != 1 || spec.AllowedHosts[0] != "a.example.com" {
		t.Errorf("AllowedHosts = %v", spec.AllowedHosts)
	}
	if spec.Substitution == nil || len(spec.Substitution.HeaderFields) != 1 {
		t.Errorf("Substitution = %+v", spec.Substitution)
	}
	if none := secretModifySpecs(nil); len(none) != 0 {
		t.Errorf("nil input produced %+v", none)
	}
}

// TestRunSecretsDispatch checks the usage errors of the secrets subcommands.
func TestRunSecretsDispatch(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"set"},
		{"set", "a", "b"},
		{"configure"},
		{"rm"},
		{"rm", "a", "b"},
		{"mv", "a"},
		{"add", "a"},
		{"ls", "a"},
	} {
		if got := runSecrets(args); got != 1 {
			t.Errorf("runSecrets(%v) = %d, want the usage error 1", args, got)
		}
	}
}

// TestRunSecretsLsEmpty lists an empty secrets dir successfully.
func TestRunSecretsLsEmpty(t *testing.T) {
	isolatedConfigDir(t)
	swapStore(t, newFakeStore(nil))
	if got := runSecrets([]string{"ls"}); got != 0 {
		t.Errorf("runSecrets(ls) = %d, want 0", got)
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

func sliceContains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
