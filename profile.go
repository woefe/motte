// Profile loading: the sandboxes/*.yaml subset this launcher understands.
//
// The files follow the microsandbox CLI's `--conf` schema.
// This loader implements exactly the subset the motte profiles use and rejects
// every other field, so a config change the launcher cannot translate fails
// loudly instead of being silently ignored.
// Files overlay left to right like repeated `--conf`: later files win field by
// field, maps merge per key, and a network section supplying `allow` replaces
// the policy part of any earlier one.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// profileDoc mirrors the supported subset of one sandboxes/*.yaml file.
// Every field is optional in a single file; the merged result must carry an
// image, and see profile for the resolved form.
type profileDoc struct {
	Image   *string              `yaml:"image"`
	CPUs    *uint8               `yaml:"cpus"`
	Memory  *string              `yaml:"memory"`
	Workdir *string              `yaml:"workdir"`
	Shell   *string              `yaml:"shell"`
	Mounts  *[]string            `yaml:"mounts"`
	Cmd     *[]string            `yaml:"cmd"`
	Scripts map[string]string    `yaml:"scripts"`
	Network *networkDoc          `yaml:"network"`
	Secrets map[string]secretDoc `yaml:"secrets"`
}

// networkDoc is the supported subset of the network section.
// A non-empty allow list implies deny-by-default egress, like the CLI.
type networkDoc struct {
	Allow *[]string `yaml:"allow"`
	TLS   *tlsDoc   `yaml:"tls"`
}

// tlsDoc is the supported subset of the network.tls section.
type tlsDoc struct {
	Enabled *bool `yaml:"enabled"`
}

// secretDoc is the supported subset of one secret declaration.
// Without a value (the only supported form), the host environment variable
// with the same name is read at launch, like the CLI.
type secretDoc struct {
	Allow        []string         `yaml:"allow"`
	Substitution *substitutionDoc `yaml:"substitution"`
}

// substitutionDoc is the supported subset of a secret substitution section.
// It defaults to headers only, restricted to header_fields when set.
type substitutionDoc struct {
	HeaderFields []string `yaml:"header_fields"`
}

// mergedDoc is the overlay-merged configuration of all profile files.
type mergedDoc struct {
	image   *string
	cpus    *uint8
	memory  *string
	workdir *string
	shell   *string
	mounts  *[]mountSpec
	cmd     *[]string
	scripts map[string]string
	network *networkDoc
	secrets map[string]secretDoc
}

// profile is one sandboxes/<name> profile merged over sandboxes/common.yaml,
// with host-relative paths resolved and secret values read from the host
// environment.
type profile struct {
	name      string
	image     string
	cpus      *uint8
	memoryMiB *uint32
	workdir   *string
	shell     *string
	mounts    []mountSpec
	cmd       []string
	scripts   map[string]string
	network   *networkDoc
	secrets   []secretSpec
}

// mountSpec is one bind-mount declaration, SOURCE:TARGET[:OPTIONS], with the
// host source resolved to an absolute path.
type mountSpec struct {
	hostPath  string
	guestPath string
	readonly  bool
	noexec    bool
	nosuid    bool
	nodev     bool
}

// secretSpec is one resolved secret declaration.
type secretSpec struct {
	envVar       string
	value        string
	allow        []string
	headerFields []string
}

// loadProfile loads sandboxes/common.yaml overlaid with
// sandboxes/<name>.yaml and resolves the merged configuration.
// getenv supplies secret values; a secret without a value fails.
func loadProfile(dir, name string, getenv func(string) string) (*profile, error) {
	merged := &mergedDoc{}
	for _, file := range []string{"common.yaml", name + ".yaml"} {
		doc, mounts, err := decodeProfileFile(filepath.Join(dir, file))
		if err != nil {
			return nil, err
		}
		merged.overlay(doc, mounts)
	}
	return newProfile(name, merged, getenv)
}

// decodeProfileFile strictly decodes one profile file and resolves its mount
// sources against the directory containing the file, like the CLI.
func decodeProfileFile(path string) (*profileDoc, []mountSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading profile file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc profileDoc
	if err := decoder.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, nil, fmt.Errorf("empty profile file %s", path)
		}
		return nil, nil, fmt.Errorf("invalid profile file %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, fmt.Errorf("invalid profile file %s: multiple YAML documents", path)
	}
	mounts, err := parseMounts(doc.Mounts, filepath.Dir(path))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return &doc, mounts, nil
}

// overlay merges one decoded file into the merged configuration; fields
// present in the later file win.
func (m *mergedDoc) overlay(doc *profileDoc, mounts []mountSpec) {
	if doc.Image != nil {
		m.image = doc.Image
	}
	if doc.CPUs != nil {
		m.cpus = doc.CPUs
	}
	if doc.Memory != nil {
		m.memory = doc.Memory
	}
	if doc.Workdir != nil {
		m.workdir = doc.Workdir
	}
	if doc.Shell != nil {
		m.shell = doc.Shell
	}
	if doc.Mounts != nil {
		m.mounts = &mounts
	}
	if doc.Cmd != nil {
		m.cmd = doc.Cmd
	}
	for name, script := range doc.Scripts {
		if m.scripts == nil {
			m.scripts = make(map[string]string)
		}
		m.scripts[name] = script
	}
	if doc.Network != nil {
		m.overlayNetwork(doc.Network)
	}
	for name, secret := range doc.Secrets {
		m.overlaySecret(name, secret)
	}
}

// overlayNetwork merges a network section; a file that supplies allow replaces
// the policy part of any earlier network section, like the CLI.
func (m *mergedDoc) overlayNetwork(n *networkDoc) {
	if m.network == nil {
		m.network = &networkDoc{}
	}
	if n.Allow != nil {
		m.network.Allow = n.Allow
	}
	if n.TLS != nil {
		if m.network.TLS == nil {
			m.network.TLS = &tlsDoc{}
		}
		if n.TLS.Enabled != nil {
			m.network.TLS.Enabled = n.TLS.Enabled
		}
	}
}

// overlaySecret merges one secret declaration, field by field.
func (m *mergedDoc) overlaySecret(name string, s secretDoc) {
	if m.secrets == nil {
		m.secrets = make(map[string]secretDoc)
	}
	current, ok := m.secrets[name]
	if !ok {
		m.secrets[name] = s
		return
	}
	if s.Allow != nil {
		current.Allow = s.Allow
	}
	if s.Substitution != nil {
		if current.Substitution == nil {
			current.Substitution = &substitutionDoc{}
		}
		if s.Substitution.HeaderFields != nil {
			current.Substitution.HeaderFields = s.Substitution.HeaderFields
		}
	}
	m.secrets[name] = current
}

// newProfile validates the merged configuration and resolves it, reading
// secret values from the host environment via getenv.
func newProfile(name string, d *mergedDoc, getenv func(string) string) (*profile, error) {
	p := &profile{name: name}
	if d.image == nil {
		return nil, fmt.Errorf("missing required sandbox field `image`; set image in sandboxes/%s.yaml", name)
	}
	p.image = *d.image
	p.cpus = d.cpus
	if d.memory != nil {
		mib, err := parseSizeMiB(*d.memory)
		if err != nil {
			return nil, fmt.Errorf("memory %q: %w", *d.memory, err)
		}
		p.memoryMiB = &mib
	}
	p.workdir = d.workdir
	p.shell = d.shell
	if d.mounts != nil {
		p.mounts = *d.mounts
	}
	if d.cmd != nil {
		p.cmd = *d.cmd
	}
	p.scripts = d.scripts
	p.network = d.network

	seen := make(map[string]bool, len(p.mounts))
	for _, mount := range p.mounts {
		if seen[mount.guestPath] {
			return nil, fmt.Errorf("duplicate guest mount target %s", mount.guestPath)
		}
		seen[mount.guestPath] = true
	}

	names := make([]string, 0, len(d.secrets))
	for envVar := range d.secrets {
		names = append(names, envVar)
	}
	slices.Sort(names) // deterministic option order, like the CLI's sorted map
	for _, envVar := range names {
		secret := d.secrets[envVar]
		value := getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("set %s in the host environment (secret declared in sandboxes/*.yaml)", envVar)
		}
		if len(secret.Allow) == 0 {
			return nil, fmt.Errorf("secret %s: allow list is empty; at least one host is required", envVar)
		}
		var headerFields []string
		if secret.Substitution != nil {
			headerFields = secret.Substitution.HeaderFields
		}
		p.secrets = append(p.secrets, secretSpec{
			envVar:       envVar,
			value:        value,
			allow:        secret.Allow,
			headerFields: headerFields,
		})
	}
	return p, nil
}

// parseMounts parses the string mounts of one file, resolving relative host
// sources against configDir, the directory of the file declaring them.
func parseMounts(mounts *[]string, configDir string) ([]mountSpec, error) {
	if mounts == nil {
		return nil, nil
	}
	out := make([]mountSpec, 0, len(*mounts))
	for _, spec := range *mounts {
		mount, err := parseMountSpec(spec, configDir)
		if err != nil {
			return nil, err
		}
		out = append(out, mount)
	}
	return out, nil
}

// parseMountSpec parses one string mount, SOURCE:TARGET[:OPTIONS], following
// the CLI grammar: the first colon separates the source, the second starts the
// option list (ro, rw, noexec, nosuid, nodev).
// A relative source resolves against configDir.
func parseMountSpec(spec, configDir string) (mountSpec, error) {
	var mount mountSpec
	sep := strings.IndexByte(spec, ':')
	if sep < 0 {
		return mount, fmt.Errorf("mount %q: expected SOURCE:TARGET[:OPTIONS]", spec)
	}
	source, rest := spec[:sep], spec[sep+1:]
	guest, options := rest, ""
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		guest, options = rest[:i], rest[i+1:]
	}
	if source == "" {
		return mount, fmt.Errorf("mount %q: empty source", spec)
	}
	if !strings.HasPrefix(guest, "/") {
		return mount, fmt.Errorf("mount %q: target %q must be an absolute guest path", spec, guest)
	}
	if !filepath.IsAbs(source) {
		source = filepath.Join(configDir, source)
	}
	mount.hostPath = source
	mount.guestPath = guest

	seen := make(map[string]bool)
	for _, option := range strings.Split(options, ",") {
		option = strings.TrimSpace(option)
		switch option {
		case "":
			// Tolerate a trailing comma.
		case "ro", "rw", "noexec", "nosuid", "nodev":
			seen[option] = true
		default:
			return mount, fmt.Errorf(
				"mount %q: unsupported option %q (supported: ro, rw, noexec, nosuid, nodev)",
				spec,
				option,
			)
		}
	}
	if seen["ro"] && seen["rw"] {
		return mount, fmt.Errorf("mount %q: conflicting options ro and rw", spec)
	}
	mount.readonly = seen["ro"]
	mount.noexec = seen["noexec"]
	mount.nosuid = seen["nosuid"]
	mount.nodev = seen["nodev"]
	return mount, nil
}
