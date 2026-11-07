// Per-directory project configs: one file per directory under
// ~/.config/motte/projects/<dir-hash>.yaml, plus the built-in image presets and
// repository toolchain detection used by `motte init`.
//
// Each project config holds the full image reference, optional extra egress
// entries (`network.allow`) and user policy groups (`network.allowGroups`),
// and the secrets injected into the sandbox (`secrets`).
package project

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
