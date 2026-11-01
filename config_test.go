package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMotteConfigTree pins the layout under the user config dir: one directory
// per config family, holding one file per scope.
func TestMotteConfigTree(t *testing.T) {
	isolatedConfigDir(t)
	root := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte")
	tests := []struct {
		dir  func() (string, error)
		want string
	}{
		{dir: motteConfigDir, want: root},
		{dir: policiesDir, want: filepath.Join(root, "policies")},
		{dir: secretsDir, want: filepath.Join(root, "secrets")},
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
	if got := motteConfigHint(); got != root {
		t.Errorf("motteConfigHint = %q, want %q", got, root)
	}
}

// TestWriteNewFileCreatesParents covers the skeleton write: missing parent
// directories are created and the contents land verbatim with the config file
// mode.
func TestWriteNewFileCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "global.yaml")
	const skeleton = "network:\n  allow: []\n"
	if err := writeNewFile(path, skeleton); err != nil {
		t.Fatalf("writeNewFile: %v", err)
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
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("%s mode = %#o, want 0644", path, perm)
	}
}
