// User policy groups: one file per group under ~/.config/motte/policies.
//
// Each group file (`<group>.yaml`) defines an `allow` list in the microsandbox
// CLI rule grammar (`TARGET[:PROTO[:PORTS]]`). Selected policy groups and
// project entries form the project's egress allow list.
package policies

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/woefe/motte/internal/config"
	"go.yaml.in/yaml/v3"
)

// ErrGroupNotFound reports a missing policy group file.
var ErrGroupNotFound = errors.New("policy group not found")

// ExtendAllow appends entries to allow, skipping ones already present.
func ExtendAllow(allow, entries []string) []string {
	out := slices.Clone(allow)
	for _, entry := range entries {
		if slices.Contains(out, entry) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// groupNamePattern matches a valid policy group slug: lowercase letters,
// digits, and dashes.
var groupNamePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidateGroupName checks that group is a valid slug filename.
func ValidateGroupName(group string) error {
	if group == "" {
		return fmt.Errorf("empty policy group name")
	}
	if !groupNamePattern.MatchString(group) {
		return fmt.Errorf(
			"invalid policy group name %q; expected lowercase letters, digits, and dashes",
			group,
		)
	}
	return nil
}

// GroupPath returns the path of a policy group file after validating the group
// name.
func GroupPath(group string) (string, error) {
	if err := ValidateGroupName(group); err != nil {
		return "", err
	}
	root, err := config.PoliciesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, group+".yaml"), nil
}

// ListGroups returns the sorted names of the configured policy groups under
// ~/.config/motte/policies.
func ListGroups() ([]string, error) {
	root, err := config.PoliciesDir()
	if err != nil {
		return nil, err
	}
	return config.ListYAMLNames(root)
}

// policyGroupDoc mirrors the policy group schema.
type policyGroupDoc struct {
	Allow []string `yaml:"allow"`
}

// ReadGroup strictly decodes one policy group file by name and returns its
// allow entries. A missing group returns ErrGroupNotFound wrapped.
func ReadGroup(group string) ([]string, error) {
	path, err := GroupPath(group)
	if err != nil {
		return nil, err
	}
	return ReadGroupFile(path)
}

// ReadGroupFile strictly decodes one policy group file at path and returns its
// allow entries. A missing file returns ErrGroupNotFound wrapped.
func ReadGroupFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("policy group %s: %w", path, ErrGroupNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("reading policy group %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc policyGroupDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil // an empty file contributes nothing
		}
		return nil, fmt.Errorf("invalid policy group %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid policy group %s: multiple YAML documents", path)
	}
	var allow []string
	for _, entry := range doc.Allow {
		if _, err := ParseAllowRule(entry); err != nil {
			return nil, fmt.Errorf("policy group %s: %w", path, err)
		}
		allow = append(allow, entry)
	}
	return allow, nil
}

// Template returns the commented skeleton of a new policy group file.
func Template(group string) (string, error) {
	if err := ValidateGroupName(group); err != nil {
		return "", err
	}
	return fmt.Sprintf(`# motte policy group — %s
# Entries are added to a project's egress allow list when selected by a project.
# Every entry uses the microsandbox CLI rule grammar, TARGET[:PROTO[:PORTS]]:
#   - "*.example.com"
#   - "host:tcp:9931"
---
allow:
  # - "*.corp.example.com"
`, group), nil
}
