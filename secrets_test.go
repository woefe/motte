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
		wantHash    string
		wantLeaf    string
		wantErr     string
	}{
		{name: "OPENCODE_GO_KEY", wantScope: scopeGlobal, wantLeaf: "OPENCODE_GO_KEY"},
		{name: "golang/OPENCODE_GO_KEY", wantScope: scopeProfile, wantProfile: "golang", wantLeaf: "OPENCODE_GO_KEY"},
		{name: "web/login_token", wantScope: scopeProfile, wantProfile: "web", wantLeaf: "login_token"},
		{name: "1234567890ab/FOO", wantScope: scopeProject, wantHash: "1234567890ab", wantLeaf: "FOO"},
		{name: "", wantErr: "empty secret name"},
		{name: "golang//FOO", wantErr: "invalid secret name"},
		{name: "a/b/c/d", wantErr: "at most two segments"},
		{name: "rails/FOO", wantScope: scopeProfile, wantProfile: "rails", wantLeaf: "FOO"},
		{name: "webserver/FOO", wantErr: "not a built-in profile"},
		{name: "web/12345/FOO", wantErr: "at most two segments"},
		{name: "golang/1234567890AB/FOO", wantErr: "at most two segments"},
		{name: "1234567890AB/FOO", wantErr: "not a built-in profile"},
		{name: "FOO-BAR", wantErr: "valid env var"},
		{name: "web/FOO.BAR", wantErr: "valid env var"},
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
			if got.scope != test.wantScope || got.profile != test.wantProfile ||
				got.hash != test.wantHash || got.leaf != test.wantLeaf {
				t.Errorf("parseSecretName(%q) = %+v, want scope/profile/hash/leaf %d/%q/%q/%q",
					test.name, got, test.wantScope, test.wantProfile, test.wantHash, test.wantLeaf)
			}
		})
	}
}

// TestSecretScopeFiles maps the scopes to their files: one file per scope,
// holding every secret of that scope.
func TestSecretScopeFiles(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name secretName
		want string
	}{
		{name: secretName{scope: scopeGlobal}, want: "global.yaml"},
		{name: secretName{scope: scopeProfile, profile: "golang"}, want: "golang.yaml"},
		{name: secretName{scope: scopeProject, hash: hash}, want: hash + ".yaml"},
	}
	for _, test := range tests {
		path, err := scopeKeyOf(test.name).path()
		if err != nil {
			t.Fatalf("path: %v", err)
		}
		if filepath.Base(path) != test.want {
			t.Errorf("path = %q, want %q", filepath.Base(path), test.want)
		}
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

// TestReadWriteSecretMeta round-trips a scope file and covers schema
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

	// The secret lives in the profile's scope file.
	scopePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "golang.yaml")
	content, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatalf("reading the scope file: %v", err)
	}
	if !strings.Contains(string(content), "OPENCODE_GO_KEY:") ||
		!strings.Contains(string(content), "*.opencode.ai") {
		t.Errorf("scope file = %q, want the secret and its hosts", string(content))
	}

	// Unknown fields fail lint-style, with the path in the error.
	writeSecretFS(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow: [\"api.example.com\"]\n    alow: [oops]\n")
	_, err = readSecretMeta(name)
	if err == nil || !strings.Contains(err.Error(), "invalid secret config") || !strings.Contains(err.Error(), "alow") {
		t.Errorf("error = %v, want an unknown-field error naming alow", err)
	}

	// A missing allow list is invalid.
	writeSecretFS(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    header_fields: [origin]\n")
	if _, err := readSecretMeta(name); err == nil || !strings.Contains(err.Error(), "empty allow list") {
		t.Errorf("error = %v, want an empty-allow error", err)
	}

	// Allow hosts must be host patterns, not network rule targets.
	writeSecretFS(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow: [\"host:tcp:9931\"]\n")
	if _, err := readSecretMeta(name); err == nil || !strings.Contains(err.Error(), "invalid secret allow host") {
		t.Errorf("error = %v, want a bad-host error", err)
	}
}

// TestSecretScopeFileKeepsCommentsAndSiblings covers the round-trip through
// the scope file: the comments and the other secrets of the scope survive an
// add and a remove.
func TestSecretScopeFileKeepsCommentsAndSiblings(t *testing.T) {
	isolatedConfigDir(t)
	writeSecretFS(t, "secrets/golang.yaml", `# the golang scope
secrets:
  # the key we use
  OPENCODE_GO_KEY:
    allow:
      - "*.opencode.ai"
`)
	first, err := parseSecretName("golang/OPENCODE_GO_KEY")
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseSecretName("golang/OTHER_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretMeta(second, secretSpec{
		allow:        []string{"other.example.com"},
		headerFields: []string{"authorization"},
	}); err != nil {
		t.Fatalf("writeSecretMeta: %v", err)
	}
	scopePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "golang.yaml")
	content, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "# the golang scope") ||
		!strings.Contains(string(content), "# the key we use") {
		t.Errorf("scope file = %q, want the comments kept", string(content))
	}
	for _, name := range []string{"OPENCODE_GO_KEY", "OTHER_SECRET"} {
		if _, err := readSecretMeta(map[string]secretName{
			"OPENCODE_GO_KEY": first,
			"OTHER_SECRET":    second,
		}[name]); err != nil {
			t.Errorf("readSecretMeta(%s): %v", name, err)
		}
	}

	// Removing a secret keeps the file and its remaining secret.
	if err := removeSecretMeta(second); err != nil {
		t.Fatalf("removeSecretMeta: %v", err)
	}
	content, err = os.ReadFile(scopePath)
	if err != nil {
		t.Fatalf("reading the scope file: %v", err)
	}
	if strings.Contains(string(content), "OTHER_SECRET") {
		t.Errorf("scope file = %q, want OTHER_SECRET removed", string(content))
	}
	if !strings.Contains(string(content), "OPENCODE_GO_KEY") {
		t.Errorf("scope file = %q, want OPENCODE_GO_KEY kept", string(content))
	}
}

// TestRemoveLastSecretRemovesTheScopeFile cleans up a scope file that holds
// no secret anymore.
func TestRemoveLastSecretRemovesTheScopeFile(t *testing.T) {
	isolatedConfigDir(t)
	name, err := parseSecretName("golang/ONLY_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretMeta(name, secretSpec{
		allow:        []string{"only.example.com"},
		headerFields: []string{"authorization"},
	}); err != nil {
		t.Fatalf("writeSecretMeta: %v", err)
	}
	if err := removeSecretMeta(name); err != nil {
		t.Fatalf("removeSecretMeta: %v", err)
	}
	scopePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "golang.yaml")
	if _, err := os.Stat(scopePath); !os.IsNotExist(err) {
		t.Errorf("scope file still exists: %v", err)
	}
	if secretMetaExists(name) {
		t.Error("the secret still exists after the removal")
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
	scopeDoc := func(allow string) string {
		return "secrets:\n  OPENCODE_GO_KEY:\n    allow:\n      - \"" + allow + "\"\n"
	}
	writeSecretFS(t, "secrets/global.yaml", scopeDoc("global.example.com"))
	writeSecretFS(t, "secrets/"+hash+".yaml", scopeDoc("project.example.com"))
	writeSecretFS(t, "secrets/golang.yaml", "secrets:\n"+
		"  OPENCODE_GO_KEY:\n    allow:\n      - \"profile.example.com\"\n"+
		"  OTHER_SECRET:\n    allow:\n      - \"other.example.com\"\n")

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

	// Another profile sees the global and the project scope, but never
	// another profile's secrets.
	effective, err = scanEffectiveSecrets("web")
	if err != nil {
		t.Fatalf("scanEffectiveSecrets(web): %v", err)
	}
	if len(effective) != 1 {
		t.Fatalf("web effective = %+v, want only the project secret", effective)
	}
	if effective[0].envVar != "OPENCODE_GO_KEY" || effective[0].allow[0] != "project.example.com" {
		t.Errorf("web effective = %+v, want the project secret", effective[0])
	}
}

// TestResolveSecrets: values come from the keychain into host env vars, egress
// extends with the secrets' allow entries, and a keychain-less secret fails
// the launch with the set hint.
func TestResolveSecrets(t *testing.T) {
	isolatedConfigDir(t)
	swapStore(t, newFakeStore(map[string]string{"OPENCODE_GO_KEY": "sk_test"}))
	writeSecretFS(t, "secrets/global.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow:\n      - \"*.opencode.ai\"\n")
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

// TestCollectLsRowsGroupsByScope covers the listing rows: one row per
// configured secret, ordered by scope.
func TestCollectLsRowsGroupsByScope(t *testing.T) {
	isolatedConfigDir(t)
	swapStore(t, newFakeStore(nil))
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	writeSecretFS(t, "secrets/global.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow:\n      - \"*.opencode.ai\"\n")
	writeSecretFS(t, "secrets/golang.yaml",
		"secrets:\n  LANG_KEY:\n    allow:\n      - \"lang.example.com\"\n")
	writeSecretFS(t, "secrets/"+hash+".yaml",
		"secrets:\n  PROJECT_KEY:\n    allow:\n      - \"project.example.com\"\n")
	rows, err := collectLsRows()
	if err != nil {
		t.Fatalf("collectLsRows: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want 3", rows)
	}
	want := []struct {
		name  string
		scope secretScope
	}{
		{name: "OPENCODE_GO_KEY", scope: scopeGlobal},
		{name: "golang/LANG_KEY", scope: scopeProfile},
		{name: hash + "/PROJECT_KEY", scope: scopeProject},
	}
	for i, expected := range want {
		if rows[i].name != expected.name || rows[i].scopeKey.scope != expected.scope {
			t.Errorf("row %d = %+v, want %q in scope %d", i, rows[i], expected.name, expected.scope)
		}
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
