// User config: optional network policies from the user config directory.
//
// ~/.config/motte/common.yaml applies to every profile;
// ~/.config/motte/<profile>.yaml adds policy for one profile. Both extend the
// built-in egress policy: entries are appended and deduplicated — user config
// can widen egress, never trim it. The strict schema only accepts
// `network.allow` entries in the CLI rule grammar; anything else fails the
// launch, with the file path in the error.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// userAllowDocs mirrors the network policies schema the launcher understands.
// Present but empty allow lists are a no-op.
type userAllowDocs struct {
	Network *userNetworkDoc `yaml:"network"`
}

// userNetworkDoc is the accepted subset of a user config network section.
type userNetworkDoc struct {
	Allow []string `yaml:"allow"`
}

// userAllow returns the network.allow entries of the user config files, in
// overlay order: common.yaml first, then the profile's own file. Missing
// files contribute nothing.
func userAllow(name string) ([]string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locating the user config dir: %w", err)
	}
	var allow []string
	for _, file := range []string{"common.yaml", name + ".yaml"} {
		entries, err := readUserAllow(filepath.Join(dir, "motte", file))
		if err != nil {
			return nil, err
		}
		allow = append(allow, entries...)
	}
	return allow, nil
}

// readUserAllow strictly decodes one user config file and returns its network
// allow entries. Entries are validated against the CLI rule grammar here so
// failures name the file, not the sandbox creation.
func readUserAllow(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading user config %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc userAllowDocs
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil // an empty file contributes nothing
		}
		return nil, fmt.Errorf("invalid user config %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid user config %s: multiple YAML documents", path)
	}
	if doc.Network == nil {
		return nil, nil
	}
	var allow []string
	for _, entry := range doc.Network.Allow {
		if _, err := parseAllowRule(entry); err != nil {
			return nil, fmt.Errorf("user config %s: %w", path, err)
		}
		allow = append(allow, entry)
	}
	return allow, nil
}
