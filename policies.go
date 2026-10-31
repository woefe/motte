// User network policies: one file per scope under ~/.config/motte/policies.
//
// global.yaml applies to every profile, <profile>.yaml to one profile, and
// <hash>.yaml to the current directory. Every file extends the built-in
// egress policy: entries are appended and deduplicated — user config can
// widen egress, never trim it. The strict schema only accepts
// `network.allow` entries in the CLI rule grammar; anything else fails the
// launch, with the file path in the error.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// policyLabelKey is the sandbox label that carries the network policy
// fingerprint, so a reused VM can be told that its policy changed.
const policyLabelKey = "motte.policy"

// policyScope is the scope a policy file applies to.
type policyScope int

const (
	scopePolicyGlobal policyScope = iota
	scopePolicyProfile
	scopePolicyProject
)

// policyTarget is a resolved policy scope: the file it lives in and the
// parts that identify it.
type policyTarget struct {
	scope   policyScope
	profile string
	hash    string
}

// policyFileDoc mirrors the network policies schema the launcher understands.
type policyFileDoc struct {
	Network *policyNetworkDoc `yaml:"network"`
}

// policyNetworkDoc is the accepted subset of a policy file's network section.
type policyNetworkDoc struct {
	Allow []string `yaml:"allow"`
}

// policiesDir returns the root of the per-user policy tree.
func policiesDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config dir: %w", err)
	}
	return filepath.Join(dir, "motte", "policies"), nil
}

// policyTargetPath maps a resolved scope to its policy file.
func policyTargetPath(target policyTarget) (string, error) {
	root, err := policiesDir()
	if err != nil {
		return "", err
	}
	name := ""
	switch target.scope {
	case scopePolicyGlobal:
		name = "global.yaml"
	case scopePolicyProfile:
		name = target.profile + ".yaml"
	case scopePolicyProject:
		name = target.hash + ".yaml"
	}
	return filepath.Join(root, name), nil
}

// policyTargetFromArg maps a resolved configure argument to its policy target.
func policyTargetFromArg(arg scopeArg) policyTarget {
	switch {
	case arg.profile != "":
		return policyTarget{scope: scopePolicyProfile, profile: arg.profile}
	case arg.hash != "":
		return policyTarget{scope: scopePolicyProject, hash: arg.hash}
	default:
		return policyTarget{scope: scopePolicyGlobal}
	}
}

// policyTargets returns the scopes that apply to a profile launch, in merge
// order: the global file, the profile's own file, and the current
// directory's project file.
func policyTargets(profileName string) ([]policyTarget, error) {
	hash, err := dirHash()
	if err != nil {
		return nil, err
	}
	return []policyTarget{
		{scope: scopePolicyGlobal},
		{scope: scopePolicyProfile, profile: profileName},
		{scope: scopePolicyProject, hash: hash},
	}, nil
}

// policyAllow returns the network.allow entries of the policy files that
// apply to a profile launch. Missing files contribute nothing.
func policyAllow(profileName string) ([]string, error) {
	targets, err := policyTargets(profileName)
	if err != nil {
		return nil, err
	}
	var allow []string
	for _, target := range targets {
		path, err := policyTargetPath(target)
		if err != nil {
			return nil, err
		}
		entries, err := readPolicyFile(path)
		if err != nil {
			return nil, err
		}
		allow = append(allow, entries...)
	}
	return allow, nil
}

// readPolicyFile strictly decodes one policy file and returns its network
// allow entries. Entries are validated against the CLI rule grammar here so
// failures name the file, not the sandbox creation.
func readPolicyFile(path string) ([]string, error) {
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
		if _, err := parseAllowRule(entry); err != nil {
			return nil, fmt.Errorf("policy %s: %w", path, err)
		}
		allow = append(allow, entry)
	}
	return allow, nil
}

// policyTemplate returns the commented skeleton of a new policy file. The
// project scope of the current directory names the directory it belongs to,
// so the file identifies its location.
func policyTemplate(target policyTarget) (string, error) {
	header := fmt.Sprintf("# motte network policy — %s\n#\n", labelScope(target.profile, target.hash, false))
	if hash, err := dirHash(); err == nil && target.scope == scopePolicyProject && hash == target.hash {
		path, err := projectPath()
		if err != nil {
			return "", err
		}
		header += fmt.Sprintf("# Project path: %s\n#\n", path)
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

// writePolicyTemplate creates a policy file with the commented skeleton.
func writePolicyTemplate(path string, target policyTarget) error {
	template, err := policyTemplate(target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(template), 0o644); err != nil {
		return fmt.Errorf("writing policy %s: %w", path, err)
	}
	return nil
}

// policyFingerprint returns a short digest of the profile's effective
// network policy. It rides along in a sandbox label, so a reused VM can be
// told that the policy it was created with is no longer the current one.
func policyFingerprint(p *profile) string {
	digest := sha256.New()
	if p.network != nil {
		if p.network.Allow != nil {
			for _, entry := range *p.network.Allow {
				_, _ = fmt.Fprintf(digest, "%s\n", entry)
			}
		}
		if p.network.TLS != nil && p.network.TLS.Enabled != nil {
			_, _ = fmt.Fprintf(digest, "tls=%t\n", *p.network.TLS.Enabled)
		}
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}
