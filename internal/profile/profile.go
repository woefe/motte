// Built-in profiles, compiled into the binary.
//
// base() carries the settings every profile shares; the profile constructors
// overlay it field by field. The network allow entries keep the microsandbox
// CLI rule-target grammar (the policies package parses it); the SDK options
// built from them behave like the CLI's. The user's policy files are merged
// on top by the launcher.
package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Profile is one built-in profile with the mount sources resolved against
// the directory motte was started in. Secrets are not part of the profile;
// they come from the user's secret configs and the OS keychain (the secrets
// package).
type Profile struct {
	Name      string
	Image     string
	CPUs      *uint8
	MemoryMiB *uint32
	Workdir   *string
	Shell     *string
	Mounts    []MountSpec
	Cmd       []string
	Scripts   map[string]string
	Network   *NetworkDoc
}

// NetworkDoc is the network configuration: an allow list in the CLI rule
// grammar (a non-empty list implies deny-by-default egress, like the CLI) and
// the TLS interception toggle.
type NetworkDoc struct {
	Allow *[]string `yaml:"-"`
	TLS   *TLSDoc   `yaml:"-"`
}

// TLSDoc is the TLS interception toggle; enabled turns on interception with
// its defaults.
type TLSDoc struct {
	Enabled *bool
}

// MountSpec is one bind-mount declaration. HostPath may be relative and is
// resolved against the directory motte was started in at launch.
type MountSpec struct {
	HostPath  string
	GuestPath string
	Readonly  bool
	Noexec    bool
	Nosuid    bool
	Nodev     bool
}

// builtins lists the profiles compiled into the binary.
var builtins = map[string]func() *Profile{
	"base":   baseProfile,
	"golang": golangProfile,
	"rails":  railsProfile,
	"web":    webProfile,
}

// Load returns the built-in profile name with the launch-time parts
// resolved: relative mount sources joined against the working directory.
func Load(name string) (*Profile, error) {
	build, ok := builtins[name]
	if !ok {
		names := Available()
		return nil, fmt.Errorf("unknown profile %s (available: %s)", name, strings.Join(names, ", "))
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolving the working directory: %w", err)
	}
	p := build()
	if err := p.resolve(cwd); err != nil {
		return nil, err
	}
	return p, nil
}

// Available returns the sorted built-in profile names.
func Available() []string {
	names := make([]string, 0, len(builtins))
	for name := range builtins {
		names = append(names, name)
	}
	slices.Sort(names) // deterministic error message
	return names
}

// resolve fills the launch-time parts of the profile: it joins relative mount
// sources with cwd. It rejects duplicate guest mount targets.
func (p *Profile) resolve(cwd string) error {
	seen := make(map[string]bool, len(p.Mounts))
	for i := range p.Mounts {
		mount := &p.Mounts[i]
		if !filepath.IsAbs(mount.HostPath) {
			mount.HostPath = filepath.Join(cwd, mount.HostPath)
		}
		if seen[mount.GuestPath] {
			return fmt.Errorf("duplicate guest mount target %s", mount.GuestPath)
		}
		seen[mount.GuestPath] = true
	}
	return nil
}

// baseAllow is the egress policy every profile shares.
var baseAllow = []string{
	"dns",
	"*.github.com",
	"*.githubusercontent.com",
	"*.opencode.ai",
	// mirrors configured in docker/base/pacman-mirrorlist
	"fastly.mirror.pkgbuild.com",
	"geo.mirror.pkgbuild.com",
	// llama.cpp on the host
	"host:tcp:9931",
	// default opencode websearch providers
	"mcp.exa.ai",
	"mcp.firecrawl.dev",
	"search.parallel.ai",
	"api.tavily.com",
	"agent.tinyfish.ai",
	// mise and sigstore for version and attestation lookups
	"mise-versions.jdx.dev",
	"tuf-repo-cdn.sigstore.dev",
	// python for mise pypi backend, which is part of the base image
	"pypi.org",
	"files.pythonhosted.org",
}

// base returns the settings every profile shares: resources, the workspace
// mount, the base egress policy extended by every profile, TLS interception,
// the connectivity check and the default cmd. Secrets are user-configured
// only (the secrets package).
func base() *Profile {
	p := &Profile{
		CPUs:      new(uint8(4)),
		MemoryMiB: new(uint32(4096)), // 4G
		Workdir:   new("/workspace"),
		Shell:     new("/bin/bash"),
		// The directory motte was started in, resolved at launch.
		Mounts: []MountSpec{{HostPath: "./", GuestPath: "/workspace"}},
		Cmd:    []string{"opencode"},
		Scripts: map[string]string{
			// Connectivity check: opencode version + llama /health.
			"check": "opencode --version && curl -sf http://host.microsandbox.internal:9931/health && echo 'llama server reachable'",
		},
		Network: &NetworkDoc{TLS: &TLSDoc{Enabled: new(true)}},
	}
	p.ExtendAllow(baseAllow)
	return p
}

// ExtendAllow widens the profile's egress policy with entries, skipping ones
// already on the list. The list is copied, so constructors never share a
// backing array.
func (p *Profile) ExtendAllow(entries []string) {
	if p.Network == nil {
		p.Network = &NetworkDoc{}
	}
	var allow []string
	if p.Network.Allow != nil {
		allow = append(allow, *p.Network.Allow...)
	}
	for _, entry := range entries {
		if slices.Contains(allow, entry) {
			continue
		}
		allow = append(allow, entry)
	}
	p.Network.Allow = &allow
}

// baseProfile extends base() with the bare base image: the shared tooling
// only (opencode, mise, git, podman), no profile-specific toolchain, and the
// shared egress policy without extras.
func baseProfile() *Profile {
	p := base()
	p.Name = "base"
	p.Image = "ghcr.io/woefe/motte/base:latest"
	return p
}

// golangProfile extends base() with the golang image and the Go toolchain's
// egress policy.
func golangProfile() *Profile {
	p := base()
	p.Name = "golang"
	p.Image = "ghcr.io/woefe/motte/golang:latest"
	p.ExtendAllow([]string{
		"go.dev",
		"dl.google.com",
		"proxy.golang.org",
		"sum.golang.org",
		"storage.googleapis.com",
	})
	return p
}

// webProfile extends base() with the web image and the node toolchain's
// egress policy.
func webProfile() *Profile {
	p := base()
	p.Name = "web"
	p.Image = "ghcr.io/woefe/motte/web:latest"
	// node: npm registry.
	p.ExtendAllow([]string{"registry.npmjs.org"})
	return p
}

// railsProfile extends base() with the rails image and the Ruby toolchain's
// egress policy.
func railsProfile() *Profile {
	p := base()
	p.Name = "rails"
	p.Image = "ghcr.io/woefe/motte/rails:latest"
	// bundler: the compact index and gem downloads; jsbundling: npm registry.
	p.ExtendAllow([]string{"rubygems.org", "index.rubygems.org", "registry.npmjs.org"})
	return p
}
