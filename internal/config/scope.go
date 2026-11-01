// Scopes: the config scopes motte addresses — global, one per built-in
// profile, and one per project directory — plus the directory identity that
// makes a project scope stable across renames and symlinks.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/woefe/motte/internal/profile"
)

// ProjectHashPattern matches a project hash: the 12-hex digest of the
// directory a project scope belongs to.
var ProjectHashPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ProjectPath returns the resolved current working directory, the directory
// the project-scoped files and sandboxes belong to. Symlinks are resolved so
// linked or renamed paths share a scope.
func ProjectPath() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving the working directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks in %s: %w", cwd, err)
	}
	return resolved, nil
}

// DirHash returns a short hash of the resolved current working directory, so
// every directory maps to one stable, unique project scope and sandbox-name
// fragment.
func DirHash() (string, error) {
	resolved, err := ProjectPath()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(resolved))
	return hex.EncodeToString(sum[:6]), nil
}

// ScopeArg is a resolved configure argument: exactly one field is set —
// profile, hash, or neither for the global scope.
type ScopeArg struct {
	Profile string
	Hash    string
}

// ResolveScopeArg resolves a configure argument: "global", "project", a
// built-in profile name, or a 12-hex project hash.
func ResolveScopeArg(arg string) (ScopeArg, error) {
	switch {
	case arg == "global":
		return ScopeArg{}, nil
	case arg == "project":
		hash, err := DirHash()
		if err != nil {
			return ScopeArg{}, err
		}
		return ScopeArg{Hash: hash}, nil
	case slices.Contains(profile.Available(), arg):
		return ScopeArg{Profile: arg}, nil
	case ProjectHashPattern.MatchString(arg):
		return ScopeArg{Hash: arg}, nil
	default:
		return ScopeArg{}, fmt.Errorf(
			"unknown scope %q; expected global, project, a profile (%s), or a project hash",
			arg, strings.Join(profile.Available(), ", "))
	}
}

// LabelScope renders a scope for listings and template headers: "global",
// "profile <name>", or "project <hash>"; thisDir marks the current
// directory's project.
func LabelScope(profileName, hash string, thisDir bool) string {
	switch {
	case profileName != "":
		return "profile " + profileName
	case hash != "":
		if thisDir {
			return "project " + hash + " (this directory)"
		}
		return "project " + hash
	default:
		return "global"
	}
}

// LsScopes returns the scopes that have a file in a config tree, ordered:
// the global scope, the built-in profiles, then the projects sorted by hash.
func LsScopes(root string) ([]ScopeArg, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	existing := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		existing[strings.TrimSuffix(entry.Name(), ".yaml")] = true
	}
	var scopes []ScopeArg
	if existing["global"] {
		scopes = append(scopes, ScopeArg{})
	}
	for _, name := range profile.Available() {
		if existing[name] {
			scopes = append(scopes, ScopeArg{Profile: name})
		}
	}
	var hashes []string
	for name := range existing {
		if ProjectHashPattern.MatchString(name) {
			hashes = append(hashes, name)
		}
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		scopes = append(scopes, ScopeArg{Hash: hash})
	}
	return scopes, nil
}
