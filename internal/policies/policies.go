// User network policies: one file per scope under ~/.config/motte/policies.
//
// global.yaml applies to every profile, <profile>.yaml to one profile, and
// <hash>.yaml to the current directory. Every file extends the built-in
// egress policy: entries are appended and deduplicated — user config can
// widen egress, never trim it. The strict schema only accepts
// `network.allow` entries in the CLI rule grammar; anything else fails the
// launch, with the file path in the error.
package policies

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/profile"
	"go.yaml.in/yaml/v3"
)

// LabelKey is the sandbox label that carries the network policy
// fingerprint, so a reused VM can be told that its policy changed.
const LabelKey = "motte.policy"

// policyFileDoc mirrors the network policies schema the launcher understands.
type policyFileDoc struct {
	Network *policyNetworkDoc `yaml:"network"`
}

// policyNetworkDoc is the accepted subset of a policy file's network section.
type policyNetworkDoc struct {
	Allow []string `yaml:"allow"`
}

// ScopePath maps a scope to its policy file.
func ScopePath(scope config.Scope) (string, error) {
	root, err := config.PoliciesDir()
	if err != nil {
		return "", err
	}
	return scope.PathIn(root), nil
}

// Allow returns the network.allow entries of the policy files that apply to a
// profile launch. Missing files contribute nothing.
func Allow(profileName string) ([]string, error) {
	scopes, err := config.EffectiveScopes(profileName)
	if err != nil {
		return nil, err
	}
	var allow []string
	for _, scope := range scopes {
		path, err := ScopePath(scope)
		if err != nil {
			return nil, err
		}
		entries, err := ReadPolicyFile(path)
		if err != nil {
			return nil, err
		}
		allow = append(allow, entries...)
	}
	return allow, nil
}

// ReadPolicyFile strictly decodes one policy file and returns its network
// allow entries. Entries are validated against the CLI rule grammar here so
// failures name the file, not the sandbox creation.
func ReadPolicyFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading policy %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc policyFileDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil // an empty file contributes nothing
		}
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid policy %s: multiple YAML documents", path)
	}
	if doc.Network == nil {
		return nil, nil
	}
	var allow []string
	for _, entry := range doc.Network.Allow {
		if _, err := ParseAllowRule(entry); err != nil {
			return nil, fmt.Errorf("policy %s: %w", path, err)
		}
		allow = append(allow, entry)
	}
	return allow, nil
}

// Template returns the commented skeleton of a new policy file. The project
// scope of the current directory names the directory it belongs to, so the
// file identifies its location.
func Template(scope config.Scope) (string, error) {
	header, err := scope.TemplateHeader("motte network policy")
	if err != nil {
		return "", err
	}
	return header + `# Entries extend the built-in egress policy; they cannot narrow it.
# Every entry uses the microsandbox CLI rule grammar, TARGET[:PROTO[:PORTS]]:
#   - "*.example.com"
#   - "host:tcp:9931"
network:
  allow:
    # - "*.example.com"
`, nil
}

// Fingerprint returns a short digest of the profile's effective network
// policy. It rides along in a sandbox label, so a reused VM can be told that
// the policy it was created with is no longer the current one.
func Fingerprint(p *profile.Profile) string {
	digest := sha256.New()
	if p.Network != nil {
		for _, entry := range p.Network.Allow {
			_, _ = fmt.Fprintf(digest, "%s\n", entry)
		}
		if p.Network.TLS != nil {
			_, _ = fmt.Fprintf(digest, "tls=%t\n", p.Network.TLS.Enabled)
		}
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}
