package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/testutil"
)

// mustDirHash returns the hash of the current directory.
func mustDirHash(t *testing.T) string {
	t.Helper()
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// readSpec returns the configured settings of a secret, failing the test
// when its scope file is invalid or the secret is missing.
func readSpec(t *testing.T, n Name) Spec {
	t.Helper()
	secrets, err := ReadScope(ScopeKeyOf(n))
	if err != nil {
		t.Fatalf("ReadScope(%s): %v", n.Full, err)
	}
	spec, ok := secrets[n.Leaf]
	if !ok {
		t.Fatalf("secret %s is not configured", n.Full)
	}
	return spec
}

// TestParseName covers the path-like name grammar per scope.
func TestParseName(t *testing.T) {
	tests := []struct {
		name        string
		wantScope   Scope
		wantProfile string
		wantHash    string
		wantLeaf    string
		wantErr     string
	}{
		{name: "OPENCODE_GO_KEY", wantScope: ScopeGlobal, wantLeaf: "OPENCODE_GO_KEY"},
		{name: "golang/OPENCODE_GO_KEY", wantScope: ScopeProfile, wantProfile: "golang", wantLeaf: "OPENCODE_GO_KEY"},
		{name: "web/login_token", wantScope: ScopeProfile, wantProfile: "web", wantLeaf: "login_token"},
		{name: "1234567890ab/FOO", wantScope: ScopeProject, wantHash: "1234567890ab", wantLeaf: "FOO"},
		{name: "", wantErr: "empty secret name"},
		{name: "golang//FOO", wantErr: "invalid secret name"},
		{name: "a/b/c/d", wantErr: "at most two segments"},
		{name: "webserver/FOO", wantErr: "not a built-in profile"},
		{name: "FOO-BAR", wantErr: "valid env var"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseName(test.name)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("ParseName(%q) error = %v, want containing %q", test.name, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseName(%q): %v", test.name, err)
			}
			if got.Scope != test.wantScope || got.Profile != test.wantProfile ||
				got.Hash != test.wantHash || got.Leaf != test.wantLeaf {
				t.Errorf("ParseName(%q) = %+v, want scope/profile/hash/leaf %d/%q/%q/%q",
					test.name, got, test.wantScope, test.wantProfile, test.wantHash, test.wantLeaf)
			}
		})
	}
}

// TestSecretScopeFiles maps the scopes to their files: one file per scope,
// holding every secret of that scope.
func TestSecretScopeFiles(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name Name
		arg  string
		want string
	}{
		{name: Name{Scope: ScopeGlobal}, arg: "global", want: "global.yaml"},
		{name: Name{Scope: ScopeProfile, Profile: "golang"}, arg: "golang", want: "golang.yaml"},
		{name: Name{Scope: ScopeProject, Hash: hash}, arg: "project", want: hash + ".yaml"},
	}
	for _, test := range tests {
		path, err := ScopeKeyOf(test.name).Path()
		if err != nil {
			t.Fatalf("Path: %v", err)
		}
		if filepath.Base(path) != test.want {
			t.Errorf("Path = %q, want %q", filepath.Base(path), test.want)
		}
		// The commands reach the same file through their scope argument.
		arg, err := config.ResolveScopeArg(test.arg)
		if err != nil {
			t.Fatalf("ResolveScopeArg(%q): %v", test.arg, err)
		}
		argPath, err := ScopeKeyFromArg(arg).Path()
		if err != nil {
			t.Fatalf("Path: %v", err)
		}
		if filepath.Base(argPath) != test.want {
			t.Errorf("Path from the %q scope = %q, want %q", test.arg, filepath.Base(argPath), test.want)
		}
	}
}

// TestValidateAllowEntry covers the host-pattern grammar of secret allow
// lists (exact hosts, *.suffix wildcards, and `*`).
func TestValidateAllowEntry(t *testing.T) {
	for _, ok := range []string{"*", "api.example.com", "*.example.com", "a.b.c.d"} {
		if err := ValidateAllowEntry(ok); err != nil {
			t.Errorf("ValidateAllowEntry(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "webserver", "localhost", "*.example.com:443", "*. *", "ex ample.com"} {
		if err := ValidateAllowEntry(bad); err == nil {
			t.Errorf("ValidateAllowEntry(%q) = nil, want an error", bad)
		}
	}
}

// TestReadWriteMeta round-trips a scope file and covers schema strictness:
// unknown fields fail, allow is required, header fields default.
func TestReadWriteMeta(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	name, err := ParseName("golang/OPENCODE_GO_KEY")
	if err != nil {
		t.Fatal(err)
	}
	spec := Spec{Allow: []string{"*.opencode.ai"}, HeaderFields: []string{"authorization"}}
	if err := WriteMeta(name, spec); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	got := readSpec(t, name)
	if got.Name != "golang/OPENCODE_GO_KEY" || got.EnvVar != "OPENCODE_GO_KEY" ||
		len(got.Allow) != 1 || got.Allow[0] != "*.opencode.ai" ||
		len(got.HeaderFields) != 1 || got.HeaderFields[0] != "authorization" {
		t.Fatalf("readSpec = %+v", got)
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
	testutil.WriteConfigFile(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow: [\"api.example.com\"]\n    alow: [oops]\n")
	_, err = ReadScope(ScopeKeyOf(name))
	if err == nil || !strings.Contains(err.Error(), "invalid secret config") || !strings.Contains(err.Error(), "alow") {
		t.Errorf("error = %v, want an unknown-field error naming alow", err)
	}

	// A missing allow list is invalid.
	testutil.WriteConfigFile(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    header_fields: [origin]\n")
	if _, err := ReadScope(ScopeKeyOf(name)); err == nil || !strings.Contains(err.Error(), "empty allow list") {
		t.Errorf("error = %v, want an empty-allow error", err)
	}

	// Allow hosts must be host patterns, not network rule targets.
	testutil.WriteConfigFile(t, "secrets/golang.yaml",
		"secrets:\n  OPENCODE_GO_KEY:\n    allow: [\"host:tcp:9931\"]\n")
	if _, err := ReadScope(ScopeKeyOf(name)); err == nil ||
		!strings.Contains(err.Error(), "invalid secret allow host") {
		t.Errorf("error = %v, want a bad-host error", err)
	}
}

// TestScopeFileKeepsCommentsAndSiblings covers the round-trip through the
// scope file: the comments and the other secrets of the scope survive an add
// and a remove.
func TestScopeFileKeepsCommentsAndSiblings(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	testutil.WriteConfigFile(t, "secrets/golang.yaml", testutil.Fixture(t, "secrets/comments/golang.yaml"))
	first, err := ParseName("golang/OPENCODE_GO_KEY")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseName("golang/OTHER_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteMeta(second, Spec{
		Allow:        []string{"other.example.com"},
		HeaderFields: []string{"authorization"},
	}); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	scopePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "golang.yaml")
	content, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatalf("reading the scope file: %v", err)
	}
	if !strings.Contains(string(content), "# the golang scope") ||
		!strings.Contains(string(content), "# the key we use") {
		t.Errorf("scope file = %q, want the comments kept", string(content))
	}
	if spec := readSpec(t, first); spec.Allow[0] != "*.opencode.ai" {
		t.Errorf("first = %+v, want the written allow list", spec)
	}
	if spec := readSpec(t, second); spec.Allow[0] != "other.example.com" {
		t.Errorf("second = %+v, want the written allow list", spec)
	}

	// Removing a secret keeps the file and its remaining secret.
	if err := RemoveMeta(second); err != nil {
		t.Fatalf("RemoveMeta: %v", err)
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
	testutil.IsolatedConfigDir(t)
	name, err := ParseName("golang/ONLY_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteMeta(name, Spec{
		Allow:        []string{"only.example.com"},
		HeaderFields: []string{"authorization"},
	}); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	if err := RemoveMeta(name); err != nil {
		t.Fatalf("RemoveMeta: %v", err)
	}
	scopePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "secrets", "golang.yaml")
	if _, err := os.Stat(scopePath); !os.IsNotExist(err) {
		t.Errorf("scope file still exists: %v", err)
	}
	secrets, err := ReadScope(ScopeKeyOf(name))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := secrets[name.Leaf]; ok {
		t.Error("the secret still exists after the removal")
	}
}

// TestScanEffectivePrecedence resolves global, profile, and project scopes
// with project > profile > global, deduping by env var name.
func TestScanEffectivePrecedence(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	scopeDoc := func(allow string) string {
		return "secrets:\n  OPENCODE_GO_KEY:\n    allow:\n      - \"" + allow + "\"\n"
	}
	testutil.WriteConfigFile(t, "secrets/global.yaml", scopeDoc("global.example.com"))
	testutil.WriteConfigFile(t, "secrets/"+hash+".yaml", scopeDoc("project.example.com"))
	testutil.WriteConfigFile(t, "secrets/golang.yaml", testutil.Fixture(t, "secrets/precedence/golang.yaml"))

	effective, err := ScanEffective("golang")
	if err != nil {
		t.Fatalf("ScanEffective: %v", err)
	}
	if len(effective) != 2 {
		t.Fatalf("effective = %+v, want 2 secrets", effective)
	}
	if effective[0].EnvVar != "OPENCODE_GO_KEY" || effective[0].Allow[0] != "project.example.com" {
		t.Errorf("OPENCODE_GO_KEY = %+v, want allow project.example.com", effective[0])
	}
	if effective[1].EnvVar != "OTHER_SECRET" || effective[1].Allow[0] != "other.example.com" {
		t.Errorf("OTHER_SECRET = %+v, want other.example.com", effective[1])
	}

	// Another profile sees the global and the project scope, but never
	// another profile's secrets.
	effective, err = ScanEffective("web")
	if err != nil {
		t.Fatalf("ScanEffective(web): %v", err)
	}
	if len(effective) != 1 {
		t.Fatalf("web effective = %+v, want only the project secret", effective)
	}
	if effective[0].EnvVar != "OPENCODE_GO_KEY" || effective[0].Allow[0] != "project.example.com" {
		t.Errorf("web effective = %+v, want the project secret", effective[0])
	}
}

// TestTemplate covers the scope-file skeletons: the settings comments, and
// the project path only for the current directory's project scope.
func TestTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	global, err := Template(ScopeKey{Scope: ScopeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(global, "secrets:") || !strings.Contains(global, "motte secrets set") {
		t.Errorf("global template = %q, want the settings comments", global)
	}
	project, err := Template(ScopeKey{Scope: ScopeProject, Hash: mustDirHash(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(project, "Project path: ") {
		t.Errorf("project template = %q, want the project path", project)
	}
	foreign, err := Template(ScopeKey{Scope: ScopeProject, Hash: "1234567890ab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(foreign, "Project path: ") {
		t.Errorf("foreign template = %q, want no project path", foreign)
	}
}

// TestParseStored covers the durable config shapes: array or map,
// HostPattern objects or strings, and the injection alias.
func TestParseStored(t *testing.T) {
	arrayShape := `{"network":{"secrets":{"secrets":[
		{"env_var":"OPENCODE_GO_KEY","value":"","source":{"kind":"env","var":"MOTTE_SECRET_OPENCODE_GO_KEY"},
		 "allowed_hosts":[{"wildcard":"*.opencode.ai"},{"exact":"api.example.com"}],
		 "substitution":{"headers":true,"header_fields":["authorization"]}},
		{"env_var":"legacy","value":"plaintext","allowed_hosts":["legacy.example.com"],
		 "injection":{"header_fields":["origin"]}}]}}}`
	stored, err := ParseStored(arrayShape)
	if err != nil {
		t.Fatalf("ParseStored: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored = %+v, want 2", stored)
	}
	first := stored[0]
	if first.EnvVar != "OPENCODE_GO_KEY" || first.Value != "" ||
		len(first.Allow) != 2 || first.Allow[0] != "*.opencode.ai" || first.Allow[1] != "api.example.com" ||
		len(first.HeaderFields) != 1 || first.HeaderFields[0] != "authorization" {
		t.Errorf("first = %+v", first)
	}
	if second := stored[1]; second.EnvVar != "legacy" || second.Value != "plaintext" ||
		len(second.Allow) != 1 || second.Allow[0] != "legacy.example.com" ||
		len(second.HeaderFields) != 1 || second.HeaderFields[0] != "origin" {
		t.Errorf("second = %+v", second)
	}

	mapShape := `{"network":{"secrets":{"secrets":{"open_key":
		{"env_var":"OPEN_KEY","value":"","allowed_hosts":[{"exact":"ok.example.com"}]}}}}}`
	stored, err = ParseStored(mapShape)
	if err != nil {
		t.Fatalf("ParseStored(map): %v", err)
	}
	if len(stored) != 1 || stored[0].EnvVar != "OPEN_KEY" || stored[0].Allow[0] != "ok.example.com" {
		t.Fatalf("map stored = %+v", stored)
	}

	// No secrets section, no entries.
	if stored, err := ParseStored(`{"network":{}}`); err != nil || stored != nil {
		t.Fatalf("empty config = %v %v", stored, err)
	}
}

// TestDrift compares stored against desired: adds, raw migrations, host
// policy changes, and removals.
func TestDrift(t *testing.T) {
	desired := []Spec{
		{EnvVar: "a_key", Allow: []string{"a.example.com"}, HeaderFields: []string{"authorization"}},
		{EnvVar: "b_key", Allow: []string{"b.example.com"}, HeaderFields: []string{"authorization"}},
	}

	// Nothing stored: everything is an add.
	upsert, remove, migrated := Drift(nil, desired)
	if len(upsert) != 2 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("nil stored: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Matching env-source stored secrets: no drift.
	upsert, remove, migrated = Drift([]Stored{
		{EnvVar: "a_key", Allow: []string{"a.example.com"}, HeaderFields: []string{"authorization"}},
		{EnvVar: "b_key", Allow: []string{"b.example.com"}, HeaderFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 0 || len(remove) != 0 || len(migrated) != 0 {
		t.Fatalf("matching: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Raw plaintext stored value: migrates to an env reference; the desired
	// b_key is not stored, so it is added in the same patch.
	upsert, remove, migrated = Drift([]Stored{
		{
			EnvVar:       "a_key",
			Value:        "plaintext",
			Allow:        []string{"a.example.com"},
			HeaderFields: []string{"authorization"},
		},
	}, desired)
	if len(upsert) != 2 || upsert[0].EnvVar != "a_key" || upsert[1].EnvVar != "b_key" ||
		len(migrated) != 1 || migrated[0] != "a_key" || len(remove) != 0 {
		t.Fatalf("raw: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// A host mismatch changes the stored rule; b_key is additionally added.
	upsert, remove, migrated = Drift([]Stored{
		{EnvVar: "a_key", Allow: []string{"other.example.com"}, HeaderFields: []string{"authorization"}},
	}, desired)
	if len(upsert) != 2 || upsert[0].EnvVar != "a_key" || len(migrated) != 0 {
		t.Fatalf("host mismatch: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}

	// Stored secrets not desired are removed.
	upsert, remove, migrated = Drift([]Stored{{EnvVar: "stale_key"}}, nil)
	if len(upsert) != 0 || len(remove) != 1 || remove[0] != "stale_key" || len(migrated) != 0 {
		t.Fatalf("stale: upsert/remove/migrated = %+v/%v/%v", upsert, remove, migrated)
	}
}
