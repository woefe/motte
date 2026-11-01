package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestResolveScopeArg resolves scope arguments to scope keys: global, the
// current project, a built-in profile, and a bare project hash.
func TestResolveScopeArg(t *testing.T) {
	isolatedConfigDir(t)
	hash, err := dirHash()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		arg  string
		want scopeArg
	}{
		{arg: "global", want: scopeArg{}},
		{arg: "project", want: scopeArg{hash: hash}},
		{arg: "golang", want: scopeArg{profile: "golang"}},
		{arg: "1234567890ab", want: scopeArg{hash: "1234567890ab"}},
	}
	for _, test := range tests {
		t.Run(test.arg, func(t *testing.T) {
			got, err := resolveScopeArg(test.arg)
			if err != nil {
				t.Fatalf("resolveScopeArg: %v", err)
			}
			if got != test.want {
				t.Errorf("resolveScopeArg(%q) = %+v, want %+v", test.arg, got, test.want)
			}
		})
	}
	if _, err := resolveScopeArg("bogus"); err == nil ||
		!strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("error = %v, want an unknown-scope error", err)
	}
}

// TestLabelScope renders each scope for listings and template headers.
func TestLabelScope(t *testing.T) {
	tests := []struct {
		profile, hash string
		thisDir       bool
		want          string
	}{
		{want: "global"},
		{profile: "golang", want: "profile golang"},
		{hash: "1234567890ab", want: "project 1234567890ab"},
		{hash: "1234567890ab", thisDir: true, want: "project 1234567890ab (this directory)"},
	}
	for _, test := range tests {
		if got := labelScope(test.profile, test.hash, test.thisDir); got != test.want {
			t.Errorf("labelScope(%q, %q, %v) = %q, want %q",
				test.profile, test.hash, test.thisDir, got, test.want)
		}
	}
}

// TestLsScopesSkipsNonScopeFiles lists only the files whose names are a scope:
// a directory, a wrong extension, and an unknown name are all skipped, and a
// config tree that does not exist yet holds no scopes. The order of the
// scopes is pinned by the ls command tests.
func TestLsScopesSkipsNonScopeFiles(t *testing.T) {
	isolatedConfigDir(t)
	root := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "motte", "policies")
	for _, name := range []string{"global.yaml", "golang.yaml", "1234567890ab.yaml", "bogus.yaml", "global.yml"} {
		writeConfigFile(t, "policies/"+name, "")
	}
	if err := os.Mkdir(filepath.Join(root, "archive.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	scopes, err := lsScopes(root)
	if err != nil {
		t.Fatalf("lsScopes: %v", err)
	}
	want := []scopeArg{{}, {profile: "golang"}, {hash: "1234567890ab"}}
	if !slices.Equal(scopes, want) {
		t.Errorf("scopes = %+v, want %+v", scopes, want)
	}
	if scopes, err = lsScopes(filepath.Join(root, "missing")); err != nil || scopes != nil {
		t.Errorf("lsScopes(missing) = %+v %v, want none without an error", scopes, err)
	}
}
