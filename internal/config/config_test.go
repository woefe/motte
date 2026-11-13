package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/woefe/motte/internal/testutil"
)

// TestMotteConfigTree pins the layout under the user config dir: one directory
// per config family.
func TestMotteConfigTree(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	root := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte")
	tests := []struct {
		dir  func() (string, error)
		want string
	}{
		{dir: ConfigDir, want: root},
		{dir: ProjectsDir, want: filepath.Join(root, "projects")},
		{dir: PoliciesDir, want: filepath.Join(root, "policies")},
		{dir: SecretsDir, want: filepath.Join(root, "secrets")},
		{dir: OpencodeDir, want: filepath.Join(root, "opencode")},
	}
	for _, test := range tests {
		got, err := test.dir()
		if err != nil {
			t.Fatalf("config dir: %v", err)
		}
		if got != test.want {
			t.Errorf("config dir = %q, want %q", got, test.want)
		}
	}
	if got := Hint(); got != root {
		t.Errorf("Hint = %q, want %q", got, root)
	}
}

// TestDirHash returns a 12-hex digest of the resolved working directory.
func TestDirHash(t *testing.T) {
	hash, err := DirHash()
	if err != nil {
		t.Fatalf("DirHash: %v", err)
	}
	if len(hash) != 12 {
		t.Errorf("DirHash = %q, want 12 hex chars", hash)
	}
}

// TestEnsureOpencodeConfig covers the default opencode.json: it is created
// when missing, and a user's edits are never overwritten.
func TestEnsureOpencodeConfig(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	dir, err := EnsureOpencodeConfig()
	if err != nil {
		t.Fatalf("EnsureOpencodeConfig: %v", err)
	}
	want, err := OpencodeDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != want {
		t.Errorf("dir = %q, want %q", dir, want)
	}
	path := filepath.Join(dir, "opencode.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(content) != defaultOpencodeConfig {
		t.Errorf("%s = %q, want the default config", path, string(content))
	}

	const custom = `{"model": "custom/model"}`
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureOpencodeConfig(); err != nil {
		t.Fatalf("EnsureOpencodeConfig: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != custom {
		t.Errorf("%s = %q, want the custom config kept", path, string(content))
	}
}

// TestWriteAtomicCreatesParents covers the config file write: missing parent
// directories are created and the contents land verbatim with the config file
// mode.
func TestWriteAtomicCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "work.yaml")
	const skeleton = "allow: []\n"
	if err := WriteAtomic(path, []byte(skeleton)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(content) != skeleton {
		t.Errorf("%s = %q, want the skeleton", path, string(content))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s mode = %#o, want 0600", path, perm)
	}
}

// TestListYAMLNames returns sorted stems of .yaml files and ignores non-YAML
// entries or missing directories.
func TestListYAMLNames(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	root, err := PoliciesDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"work-vpn.yaml", "corp.yaml", "ignore.yml"} {
		testutil.WriteConfigFile(t, "policies/"+name, "")
	}
	if err := os.Mkdir(filepath.Join(root, "subdir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	names, err := ListYAMLNames(root)
	if err != nil {
		t.Fatalf("ListYAMLNames: %v", err)
	}
	want := []string{"corp", "work-vpn"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	if missing, err := ListYAMLNames(filepath.Join(root, "missing")); err != nil || missing != nil {
		t.Errorf("ListYAMLNames(missing) = %v %v, want nil", missing, err)
	}
}
