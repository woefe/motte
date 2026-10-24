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
// sources resolved against the directory motte was started in and secret
// values read from the host environment.
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

// secretSpec is one secret declaration. The value comes from the host
// environment variable envVar at launch.
type secretSpec struct {
	envVar       string
	value        string
	allow        []string
	headerFields []string
}

// builtins lists the profiles compiled into the binary.
var builtins = map[string]func() *profile{
	"golang": golangProfile,
	"web":    webProfile,
}

// loadProfile returns the built-in profile name with the launch-time parts
// resolved: relative mount sources joined against the working directory and
// secret values read from getenv.
func loadProfile(name string, getenv func(string) string) (*profile, error) {
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
	if err := p.resolve(cwd, getenv); err != nil {
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
// sources with cwd, and reads each secret's value from getenv. It rejects
// duplicate guest mount targets and secrets without a value.
func (p *profile) resolve(cwd string, getenv func(string) string) error {
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
	for i := range p.secrets {
		secret := &p.secrets[i]
		value := getenv(secret.envVar)
		if value == "" {
			return fmt.Errorf("set %s in the host environment for the %s profile", secret.envVar, p.name)
		}
		if len(secret.allow) == 0 {
			return fmt.Errorf("secret %s: allow list is empty; at least one host is required", secret.envVar)
		}
		secret.value = value
	}
	return nil
}

// base returns the settings every profile shares: resources, the workspace
// mount, TLS interception, the OpenCode Go secret, the connectivity check and
// the default cmd.
func base() *profile {
	return &profile{
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
		secrets: []secretSpec{{
			// OpenCode Go token read from the host env at sandbox start.
			envVar:       "OPENCODE_GO_KEY",
			allow:        []string{"*.opencode.ai"},
			headerFields: []string{"authorization", "x-api-key"},
		}},
	}
}

// golangProfile overlays base() with the golang image and egress policy.
func golangProfile() *profile {
	p := base()
	p.name = "golang"
	p.image = "ghcr.io/woefe/motte/golang:latest"
	// gateway DNS, github (git/API/releases), opencode provider, llama host
	// port; mise: version/attestation lookups + sigstore TUF trust root; go
	// toolchain + module proxy; arch package mirrors (kept in sync with
	// docker/pacman-mirrorlist); llama.cpp server on the host; websearch
	// providers (opencode mcp endpoints); project specific.
	p.network.Allow = ptr([]string{
		"dns",
		"*.github.com",
		"*.githubusercontent.com",
		"*.opencode.ai",
		"mise-versions.jdx.dev",
		"tuf-repo-cdn.sigstore.dev",
		"go.dev",
		"dl.google.com",
		"proxy.golang.org",
		"sum.golang.org",
		"storage.googleapis.com",
		"fastly.mirror.pkgbuild.com",
		"geo.mirror.pkgbuild.com",
		"host:tcp:9931",
		"mcp.exa.ai",
		"mcp.firecrawl.dev",
		"search.parallel.ai",
		"api.tavily.com",
		"agent.tinyfish.ai",
		"docs.microsandbox.dev",
		"pypi.org", // for yamllint
		"taskfile.dev",
		"files.pythonhosted.org",
	})
	return p
}

// webProfile overlays base() with the web image and egress policy.
func webProfile() *profile {
	p := base()
	p.name = "web"
	p.image = "ghcr.io/woefe/motte/web:latest"
	// gateway DNS, github (git/API/releases), opencode provider; python: pypi
	// index + file CDN; node: npm registry; mise: version/attestation lookups
	// + sigstore TUF trust root; arch package mirrors (kept in sync with
	// docker/pacman-mirrorlist); llama.cpp server on the host; websearch
	// providers (opencode mcp endpoints).
	p.network.Allow = ptr([]string{
		"dns",
		"*.github.com",
		"*.githubusercontent.com",
		"*.opencode.ai",
		"pypi.org",
		"files.pythonhosted.org",
		"registry.npmjs.org",
		"mise-versions.jdx.dev",
		"tuf-repo-cdn.sigstore.dev",
		"fastly.mirror.pkgbuild.com",
		"geo.mirror.pkgbuild.com",
		"host:tcp:9931",
		"mcp.exa.ai",
		"mcp.firecrawl.dev",
		"search.parallel.ai",
		"api.tavily.com",
		"agent.tinyfish.ai",
	})
	return p
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}
