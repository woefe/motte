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

// Scope identifies a configuration scope: global (both fields empty),
// a built-in profile (Profile set), or a project directory (Hash set).
type Scope struct {
	Profile string
	Hash    string
}

// ResolveScope resolves a configure argument: "global", "project", a
// built-in profile name, or a 12-hex project hash.
func ResolveScope(arg string) (Scope, error) {
	switch {
	case arg == "global":
		return Scope{}, nil
	case arg == "project":
		hash, err := DirHash()
		if err != nil {
			return Scope{}, err
		}
		return Scope{Hash: hash}, nil
	case slices.Contains(profile.Available(), arg):
		return Scope{Profile: arg}, nil
	case ProjectHashPattern.MatchString(arg):
		return Scope{Hash: arg}, nil
	default:
		return Scope{}, fmt.Errorf(
			"unknown scope %q; expected global, project, a profile (%s), or a project hash",
			arg, strings.Join(profile.Available(), ", "))
	}
}

// EffectiveScopes returns the scopes that apply to a profile launch in merge
// order: the global scope, the profile's own scope, and the current
// directory's project scope.
func EffectiveScopes(profileName string) ([]Scope, error) {
	hash, err := DirHash()
	if err != nil {
		return nil, err
	}
	return []Scope{
		{},
		{Profile: profileName},
		{Hash: hash},
	}, nil
}

// Prefix returns the scope prefix of a path-like name: "" for global, the
// profile name, or the project hash.
func (s Scope) Prefix() string {
	switch {
	case s.Profile != "":
		return s.Profile
	case s.Hash != "":
		return s.Hash
	default:
		return ""
	}
}

// QualifiedName prefixes leaf with the scope prefix when non-global.
func (s Scope) QualifiedName(leaf string) string {
	if prefix := s.Prefix(); prefix != "" {
		return prefix + "/" + leaf
	}
	return leaf
}

// ConfigureArg renders the scope as a `configure` CLI argument.
func (s Scope) ConfigureArg() string {
	switch {
	case s.Profile != "":
		return s.Profile
	case s.Hash != "":
		if hash, err := DirHash(); err == nil && hash == s.Hash {
			return "project"
		}
		return s.Hash
	default:
		return "global"
	}
}

// FileName returns the YAML file basename for the scope.
func (s Scope) FileName() string {
	if prefix := s.Prefix(); prefix != "" {
		return prefix + ".yaml"
	}
	return "global.yaml"
}

// PathIn joins the scope's YAML file basename onto root.
func (s Scope) PathIn(root string) string {
	return filepath.Join(root, s.FileName())
}

// Label renders the scope for listings and template headers: "global",
// "profile <name>", or "project <hash>"; thisDir marks the current
// directory's project.
func (s Scope) Label(thisDir bool) string {
	switch {
	case s.Profile != "":
		return "profile " + s.Profile
	case s.Hash != "":
		if thisDir {
			return "project " + s.Hash + " (this directory)"
		}
		return "project " + s.Hash
	default:
		return "global"
	}
}

// TemplateHeader renders the commented header of a new scope file, naming the
// directory when the scope is the current directory's project scope.
func (s Scope) TemplateHeader(kind string) (string, error) {
	header := fmt.Sprintf("# %s — %s\n#\n", kind, s.Label(false))
	if hash, err := DirHash(); err == nil && s.Hash != "" && hash == s.Hash {
		path, err := ProjectPath()
		if err != nil {
			return "", err
		}
		header += fmt.Sprintf("# Project path: %s\n#\n", path)
	}
	return header, nil
}

// LsScopes returns the scopes that have a file in a config tree, ordered:
// the global scope, the built-in profiles, then the projects sorted by hash.
func LsScopes(root string) ([]Scope, error) {
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
	var scopes []Scope
	if existing["global"] {
		scopes = append(scopes, Scope{})
	}
	for _, name := range profile.Available() {
		if existing[name] {
			scopes = append(scopes, Scope{Profile: name})
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
		scopes = append(scopes, Scope{Hash: hash})
	}
	return scopes, nil
}
