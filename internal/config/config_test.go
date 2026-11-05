package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/woefe/motte/internal/testutil"
)

// TestMotteConfigTree pins the layout under the user config dir: one directory
// per config family, holding one file per scope.
func TestMotteConfigTree(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	root := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte")
	tests := []struct {
		dir  func() (string, error)
		want string
	}{
		{dir: ConfigDir, want: root},
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

// TestWriteNewFileCreatesParents covers the skeleton write: missing parent
// directories are created and the contents land verbatim with the config file
// mode.
func TestWriteNewFileCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "global.yaml")
	const skeleton = "network:\n  allow: []\n"
	if err := WriteNewFile(path, skeleton); err != nil {
		t.Fatalf("WriteNewFile: %v", err)
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
