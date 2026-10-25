// Built-in profiles, compiled into the binary.
//
// base() carries the settings every profile shares; the profile constructors
// overlay it, mirroring the old `--conf` overlay semantics field by field. The network allow entries
// keep the microsandbox CLI rule-target grammar (see sdk.go); the SDK options
// built from them behave like the CLI's.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// profile is one resolved profile: a built-in definition with the mount
// sources resolved against the directory motte was started in. Secrets are
// not part of the profile; they come from the user's secret configs and the
// OS keychain (see secrets.go).
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
}

// networkDoc is the network configuration: an allow list in the CLI rule
// grammar (a non-empty list implies deny-by-default egress, like the CLI) and
// the TLS interception toggle.
type networkDoc struct {
	Allow *[]string `yaml:"-"`
	TLS   *tlsDoc   `yaml:"-"`
}

// tlsDoc is the TLS interception toggle; enabled turns on interception with
// its defaults.
type tlsDoc struct {
	Enabled *bool
}

// mountSpec is one bind-mount declaration. hostPath may be relative and is
// resolved against the directory motte was started in at launch.
type mountSpec struct {
	hostPath  string
	guestPath string
	readonly  bool
	noexec    bool
	nosuid    bool
	nodev     bool
}

// secretSpec is defined in secrets.go: one user-configured secret with its
// keychain-backed value, allow list, and header fields.

// builtins lists the profiles compiled into the binary.
var builtins = map[string]func() *profile{
	"golang": golangProfile,
	"web":    webProfile,
}

// loadProfile returns the built-in profile name with the launch-time parts
// resolved: relative mount sources joined against the working directory.
func loadProfile(name string) (*profile, error) {
	build, ok := builtins[name]
	if !ok {
		names := availableProfiles()
		return nil, fmt.Errorf("unknown profile %s (available: %s)", name, strings.Join(names, ", "))
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolving the working directory: %w", err)
	}
	p := build()
	extra, err := userAllow(name)
	if err != nil {
		return nil, err
	}
	p.extendAllow(extra)
	if err := p.resolve(cwd); err != nil {
		return nil, err
	}
	return p, nil
}

// availableProfiles returns the sorted built-in profile names.
func availableProfiles() []string {
	names := make([]string, 0, len(builtins))
	for name := range builtins {
		names = append(names, name)
	}
	slices.Sort(names) // deterministic error message
	return names
}

// resolve fills the launch-time parts of the profile: it joins relative mount
// sources with cwd. It rejects duplicate guest mount targets.
func (p *profile) resolve(cwd string) error {
	seen := make(map[string]bool, len(p.mounts))
	for i := range p.mounts {
		mount := &p.mounts[i]
		if !filepath.IsAbs(mount.hostPath) {
			mount.hostPath = filepath.Join(cwd, mount.hostPath)
		}
		if seen[mount.guestPath] {
			return fmt.Errorf("duplicate guest mount target %s", mount.guestPath)
		}
		seen[mount.guestPath] = true
	}
	return nil
}

// baseAllow is the egress policy every profile shares
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
// only (see secrets.go).
func base() *profile {
	p := &profile{
		cpus:      ptr(uint8(4)),
		memoryMiB: ptr(uint32(4096)), // 4G
		workdir:   ptr("/workspace"),
		shell:     ptr("/bin/bash"),
		// The directory motte was started in, resolved at launch.
		mounts: []mountSpec{{hostPath: "./", guestPath: "/workspace"}},
		cmd:    []string{"opencode"},
		scripts: map[string]string{
			// Connectivity check: opencode version + llama /health.
			"check": "opencode --version && curl -sf http://host.microsandbox.internal:9931/health && echo 'llama server reachable'",
		},
		network: &networkDoc{TLS: &tlsDoc{Enabled: ptr(true)}},
	}
	p.extendAllow(baseAllow)
	return p
}

// extendAllow widens the profile's egress policy with entries, skipping ones
// already on the list. The list is copied, so constructors never share a
// backing array.
func (p *profile) extendAllow(entries []string) {
	if p.network == nil {
		p.network = &networkDoc{}
	}
	var allow []string
	if p.network.Allow != nil {
		allow = append(allow, *p.network.Allow...)
	}
	for _, entry := range entries {
		if slices.Contains(allow, entry) {
			continue
		}
		allow = append(allow, entry)
	}
	p.network.Allow = &allow
}

// golangProfile extends base() with the golang image and the Go toolchain's
// egress policy.
func golangProfile() *profile {
	p := base()
	p.name = "golang"
	p.image = "ghcr.io/woefe/motte/golang:latest"
	p.extendAllow([]string{
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
func webProfile() *profile {
	p := base()
	p.name = "web"
	p.image = "ghcr.io/woefe/motte/web:latest"
	// node: npm registry.
	p.extendAllow([]string{"registry.npmjs.org"})
	return p
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}
