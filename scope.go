// Scopes: the config scopes motte addresses — global, one per built-in
// profile, and one per project directory — plus the directory identity that
// makes a project scope stable across renames and symlinks.
package main

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
)

// projectHashPattern matches a project hash: the 12-hex digest of the
// directory a project scope belongs to.
var projectHashPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// projectPath returns the resolved current working directory, the directory
// the project-scoped files and sandboxes belong to. Symlinks are resolved so
// linked or renamed paths share a scope.
func projectPath() (string, error) {
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

// dirHash returns a short hash of the resolved current working directory, so
// every directory maps to one stable, unique project scope and sandbox-name
// fragment.
func dirHash() (string, error) {
	resolved, err := projectPath()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(resolved))
	return hex.EncodeToString(sum[:6]), nil
}

// scopeArg is a resolved configure argument: exactly one field is set —
// profile, hash, or neither for the global scope.
type scopeArg struct {
	profile string
	hash    string
}

// resolveScopeArg resolves a configure argument: "global", "project", a
// built-in profile name, or a 12-hex project hash.
func resolveScopeArg(arg string) (scopeArg, error) {
	switch {
	case arg == "global":
		return scopeArg{}, nil
	case arg == "project":
		hash, err := dirHash()
		if err != nil {
			return scopeArg{}, err
		}
		return scopeArg{hash: hash}, nil
	case slices.Contains(availableProfiles(), arg):
		return scopeArg{profile: arg}, nil
	case projectHashPattern.MatchString(arg):
		return scopeArg{hash: arg}, nil
	default:
		return scopeArg{}, fmt.Errorf(
			"unknown scope %q; expected global, project, a profile (%s), or a project hash",
			arg, strings.Join(availableProfiles(), ", "))
	}
}

// labelScope renders a scope for listings and template headers: "global",
// "profile <name>", or "project <hash>"; thisDir marks the current
// directory's project.
func labelScope(profile, hash string, thisDir bool) string {
	switch {
	case profile != "":
		return "profile " + profile
	case hash != "":
		if thisDir {
			return "project " + hash + " (this directory)"
		}
		return "project " + hash
	default:
		return "global"
	}
}

// lsScopes returns the scopes that have a file in a config tree, ordered:
// the global scope, the built-in profiles, then the projects sorted by hash.
func lsScopes(root string) ([]scopeArg, error) {
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
	var scopes []scopeArg
	if existing["global"] {
		scopes = append(scopes, scopeArg{})
	}
	for _, profile := range availableProfiles() {
		if existing[profile] {
			scopes = append(scopes, scopeArg{profile: profile})
		}
	}
	var hashes []string
	for name := range existing {
		if projectHashPattern.MatchString(name) {
			hashes = append(hashes, name)
		}
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		scopes = append(scopes, scopeArg{hash: hash})
	}
	return scopes, nil
}
