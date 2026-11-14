// Per-directory project configs: one file per directory under
// ~/.config/motte/projects/<dir-hash>.yaml, plus the built-in image presets,
// repository toolchain detection, and launch-time project resolution.
//
// Each project config holds the full image reference, optional extra egress
// entries (`network.allow`) and user policy groups (`network.allowGroups`),
// and the secrets injected into the sandbox (`secrets`).
package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/secrets"
	"go.yaml.in/yaml/v3"
)

// ErrNotFound reports that a directory has no project config yet.
var ErrNotFound = errors.New("project config not found")

// presets maps the built-in image preset names to their GHCR image references.
var presets = map[string]string{
	"base":   "ghcr.io/woefe/motte/base:latest",
	"golang": "ghcr.io/woefe/motte/golang:latest",
	"rails":  "ghcr.io/woefe/motte/rails:latest",
	"web":    "ghcr.io/woefe/motte/web:latest",
}

// Presets returns the sorted built-in image preset names.
func Presets() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// PresetImage returns the full GHCR image reference for a built-in preset
// name.
func PresetImage(name string) (string, bool) {
	image, ok := presets[name]
	return image, ok
}

// PresetName returns the built-in preset name for a full image reference, if
// it matches one.
func PresetName(image string) (string, bool) {
	for name, ref := range presets {
		if ref == image {
			return name, true
		}
	}
	return "", false
}

// DetectPreset inspects dir for toolchain files (`go.mod` -> golang,
// `Gemfile` -> rails, `package.json` -> web) and otherwise returns "base".
func DetectPreset(dir string) string {
	checks := []struct {
		file   string
		preset string
	}{
		{file: "go.mod", preset: "golang"},
		{file: "Gemfile", preset: "rails"},
		{file: "package.json", preset: "web"},
	}
	for _, check := range checks {
		if info, err := os.Stat(filepath.Join(dir, check.file)); err == nil && !info.IsDir() {
			return check.preset
		}
	}
	return "base"
}

// Config is the validated configuration of one directory's project.
type Config struct {
	Image       string
	Allow       []string
	AllowGroups []string
	Secrets     []string
}

// ResolvedSecret is one secret resolved for a sandbox launch: its env var name,
// the host env var its value travels in, its allowed hosts, and its header
// fields.
type ResolvedSecret struct {
	EnvVar       string
	HostEnv      string
	Allow        []string
	HeaderFields []string
}

// Resolved holds everything the launcher needs to boot the current directory's
// project sandbox.
type Resolved struct {
	SandboxName  string
	Image        string
	WorkspaceDir string
	OpencodeDir  string
	Rules        []msb.PolicyRule
	Fingerprint  string
	Secrets      []ResolvedSecret
}

// ClearSecretEnv unsets the host environment variables exported for the
// resolved secrets.
func (r Resolved) ClearSecretEnv() {
	unsetSecretEnv(r.Secrets)
}

// projectFileDoc mirrors the project config YAML schema.
type projectFileDoc struct {
	Image   string             `yaml:"image"`
	Network *projectNetworkDoc `yaml:"network,omitempty"`
	Secrets []string           `yaml:"secrets,omitempty"`
}

// projectNetworkDoc is the network section of a project config.
type projectNetworkDoc struct {
	Allow       []string `yaml:"allow,omitempty"`
	AllowGroups []string `yaml:"allowGroups,omitempty"`
}

// CurrentPath returns the path to the current directory's project config file.
func CurrentPath() (string, error) {
	hash, err := config.DirHash()
	if err != nil {
		return "", err
	}
	return PathForHash(hash)
}

// PathForHash returns the path to a project config file by its directory hash.
func PathForHash(hash string) (string, error) {
	root, err := config.ProjectsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, hash+".yaml"), nil
}

// ReadCurrent strictly decodes the current directory's project config and
// returns it alongside its file path. If the file does not exist, it returns
// ErrNotFound wrapped.
func ReadCurrent() (Config, string, error) {
	path, err := CurrentPath()
	if err != nil {
		return Config{}, "", err
	}
	cfg, err := ReadFile(path)
	if err != nil {
		return Config{}, path, err
	}
	return cfg, path, nil
}

// ReadFile strictly decodes a project config file at path. A missing file
// returns ErrNotFound wrapped; schema or entry errors include path.
func ReadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("project %s: %w", path, ErrNotFound)
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading project config %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc projectFileDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return Config{}, fmt.Errorf("invalid project config %s: image is required", path)
		}
		return Config{}, fmt.Errorf("invalid project config %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Config{}, fmt.Errorf("invalid project config %s: multiple YAML documents", path)
	}
	image := strings.TrimSpace(doc.Image)
	if image == "" {
		return Config{}, fmt.Errorf("invalid project config %s: image is required", path)
	}
	if !strings.Contains(image, "/") {
		return Config{}, fmt.Errorf(
			"invalid project config %s: image %q must be a full image reference",
			path,
			image,
		)
	}

	var allow, allowGroups []string
	if doc.Network != nil {
		for _, entry := range doc.Network.Allow {
			if _, err := policies.ParseAllowRule(entry); err != nil {
				return Config{}, fmt.Errorf("project config %s: %w", path, err)
			}
			allow = append(allow, entry)
		}
		for _, group := range doc.Network.AllowGroups {
			if err := policies.ValidateGroupName(group); err != nil {
				return Config{}, fmt.Errorf("project config %s: %w", path, err)
			}
			allowGroups = append(allowGroups, group)
		}
	}
	for _, sec := range doc.Secrets {
		if err := secrets.ValidateName(sec); err != nil {
			return Config{}, fmt.Errorf("project config %s: %w", path, err)
		}
	}
	return Config{
		Image:       image,
		Allow:       allow,
		AllowGroups: allowGroups,
		Secrets:     doc.Secrets,
	}, nil
}

// WriteCurrent writes cfg to the current directory's project config file
// atomically with 0600 permissions, including the `# Project path:` comment.
func WriteCurrent(cfg Config) (string, error) {
	path, err := CurrentPath()
	if err != nil {
		return "", err
	}
	projectDir, err := config.ProjectPath()
	if err != nil {
		return "", err
	}
	if err := WriteFile(path, projectDir, cfg); err != nil {
		return "", err
	}
	return path, nil
}

// WriteFile writes cfg to path with the `# Project path:` header comment.
func WriteFile(path, projectDir string, cfg Config) error {
	doc := projectFileDoc{
		Image:   cfg.Image,
		Secrets: cfg.Secrets,
	}
	if len(cfg.Allow) > 0 || len(cfg.AllowGroups) > 0 {
		doc.Network = &projectNetworkDoc{
			Allow:       cfg.Allow,
			AllowGroups: cfg.AllowGroups,
		}
	}
	var buf bytes.Buffer
	buf.WriteString("# motte project\n")
	if projectDir != "" {
		fmt.Fprintf(&buf, "# Project path: %s\n", projectDir)
	}
	buf.WriteString("---\n")
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("serializing project config %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("serializing project config %s: %w", path, err)
	}
	return config.WriteAtomic(path, buf.Bytes())
}

// EffectiveAllow computes the deduplicated egress allow list for a project
// config: every selected policy group plus the project's network.allow entries.
// A selected group without a file fails with projectPath in the error.
func EffectiveAllow(proj Config, projectPath string) ([]string, error) {
	var allow []string
	for _, group := range proj.AllowGroups {
		entries, err := policies.ReadGroup(group)
		if errors.Is(err, policies.ErrGroupNotFound) {
			return nil, fmt.Errorf(
				"project config %s: policy group %q does not exist; create it with `motte policies configure %s`",
				projectPath, group, group,
			)
		}
		if err != nil {
			return nil, err
		}
		allow = policies.ExtendAllow(allow, entries)
	}
	allow = policies.ExtendAllow(allow, proj.Allow)
	return allow, nil
}

// ParseRules translates an allow list in the CLI rule grammar into SDK egress
// allow rules.
func ParseRules(allow []string) ([]msb.PolicyRule, error) {
	rules := make([]msb.PolicyRule, 0, len(allow))
	for _, entry := range allow {
		rule, err := policies.ParseAllowRule(entry)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Fingerprint returns a short digest of the sandbox's image and effective
// network allow list. It rides along in a sandbox label, so a reused VM can be
// told that the image or policy it was created with is no longer current.
func Fingerprint(image string, allow []string) string {
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "image=%s\n", image)
	for _, entry := range allow {
		_, _ = fmt.Fprintf(digest, "%s\n", entry)
	}
	return hex.EncodeToString(digest.Sum(nil)[:8])
}

// ResolveCurrent loads and resolves the current directory's project for a
// sandbox launch, exporting selected secrets from the default OS keychain into
// host env vars. The caller must call Resolved.ClearSecretEnv() once the
// sandbox has booted.
func ResolveCurrent() (Resolved, error) {
	return resolveCurrentWithStore(secrets.DefaultStore())
}

// resolveCurrentWithStore resolves the current directory's project against
// store.
func resolveCurrentWithStore(store secrets.Store) (Resolved, error) {
	proj, projectPath, err := ReadCurrent()
	if errors.Is(err, ErrNotFound) {
		return Resolved{}, fmt.Errorf(
			"no project configured for this directory (%s); run `motte init` first",
			projectPath,
		)
	}
	if err != nil {
		return Resolved{}, err
	}
	allow, err := EffectiveAllow(proj, projectPath)
	if err != nil {
		return Resolved{}, err
	}
	rules, err := ParseRules(allow)
	if err != nil {
		return Resolved{}, err
	}
	workspaceDir, err := config.ProjectPath()
	if err != nil {
		return Resolved{}, err
	}
	hash, err := config.DirHash()
	if err != nil {
		return Resolved{}, err
	}
	opencodeDir, err := config.EnsureOpencodeConfig()
	if err != nil {
		return Resolved{}, err
	}
	resolvedSecrets, err := resolveSecrets(proj.Secrets, store)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		SandboxName:  "motte-" + hash,
		Image:        proj.Image,
		WorkspaceDir: workspaceDir,
		OpencodeDir:  opencodeDir,
		Rules:        rules,
		Fingerprint:  Fingerprint(proj.Image, allow),
		Secrets:      resolvedSecrets,
	}, nil
}

// resolveSecrets loads the settings and keychain values of the selected secret
// names into host env vars for the sandbox boot. Secret allow hosts do not
// widen the network egress allow list.
func resolveSecrets(selected []string, store secrets.Store) ([]ResolvedSecret, error) {
	var resolved []ResolvedSecret
	seen := make(map[string]bool, len(selected))
	for _, name := range selected {
		if seen[name] {
			continue
		}
		seen[name] = true
		spec, err := secrets.Read(name)
		if errors.Is(err, secrets.ErrNotFound) {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf(
				"secret %s is not configured — create it with: motte secrets add",
				name,
			)
		}
		if err != nil {
			unsetSecretEnv(resolved)
			return nil, err
		}
		value, err := store.Get(spec.Name)
		if errors.Is(err, secrets.ErrNotFound) {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf(
				"secret %s is not in the keychain — set it with: motte secrets set %s",
				spec.Name, spec.Name,
			)
		}
		if err != nil {
			unsetSecretEnv(resolved)
			return nil, err
		}
		hostEnv := secrets.HostEnvVar(spec.EnvVar)
		if err := os.Setenv(hostEnv, value); err != nil {
			unsetSecretEnv(resolved)
			return nil, fmt.Errorf("exporting %s: %w", hostEnv, err)
		}
		resolved = append(resolved, ResolvedSecret{
			EnvVar:       spec.EnvVar,
			HostEnv:      hostEnv,
			Allow:        spec.Allow,
			HeaderFields: spec.HeaderFields,
		})
	}
	return resolved, nil
}

// unsetSecretEnv clears the host env vars secrets resolve through.
func unsetSecretEnv(resolved []ResolvedSecret) {
	for _, sec := range resolved {
		_ = os.Unsetenv(sec.HostEnv)
	}
}
