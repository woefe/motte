// Translation of a merged profile into microsandbox Go SDK options.
//
// The translations mirror how the msb CLI resolves the same YAML values
// (crates/cli of the microsandbox sources): sizes are GiB/MiB-based, network
// allow entries follow the rule-target grammar TARGET[:PROTO[:PORTS]] with a
// non-empty allow list implying deny-by-default egress, and `network.tls.
// enabled: true` turns on TLS interception with its defaults.
package launcher

import (
	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/profile"
	"github.com/woefe/motte/internal/secrets"
)

// sandboxOptions translates a profile into the options for creating the
// profile's sandbox. Replacing an existing VM is the launcher's call (see
// --replace), so no replace option is set here.
// With noPull set it leaves the image pull policy at the runtime default (pull
// only if missing) so a locally loaded image wins; otherwise it always
// refreshes the image.
func sandboxOptions(p *profile.Profile, noPull bool) ([]m.SandboxOption, error) {
	opts := []m.SandboxOption{
		m.WithImage(p.Image),
		// The fingerprint of the effective network policy, so a reused VM
		// can be told that its policy is no longer the current one.
		m.WithLabels(map[string]string{policies.LabelKey: policies.Fingerprint(p)}),
	}
	if p.CPUs != nil {
		opts = append(opts, m.WithCPUs(*p.CPUs))
	}
	if p.MemoryMiB != nil {
		opts = append(opts, m.WithMemory(*p.MemoryMiB))
	}
	if p.Workdir != nil {
		opts = append(opts, m.WithWorkdir(*p.Workdir))
	}
	if p.Shell != nil {
		opts = append(opts, m.WithShell(*p.Shell))
	}
	if len(p.Mounts) > 0 {
		mounts := make(map[string]m.MountConfig, len(p.Mounts))
		for _, mount := range p.Mounts {
			mounts[mount.GuestPath] = m.Mount.Bind(mount.HostPath, m.MountOptions{
				Readonly: mount.Readonly,
				Noexec:   mount.Noexec,
				Nosuid:   mount.Nosuid,
				Nodev:    mount.Nodev,
			})
		}
		opts = append(opts, m.WithMounts(mounts))
	}
	if p.Cmd != nil {
		opts = append(opts, m.WithCmd(p.Cmd...))
	}
	if len(p.Scripts) > 0 {
		opts = append(opts, m.WithScripts(p.Scripts))
	}
	if p.Network != nil {
		network, err := networkConfig(p.Network)
		if err != nil {
			return nil, err
		}
		opts = append(opts, m.WithNetwork(network))
	}
	// Secrets are deliberately absent here: create-time raw values persist
	// plaintext in the durable sandbox config on the host. Secrets are
	// applied after creation instead, as env-source modify entries — see
	// convergeAfterCreate and secretModifySpecs.
	if !noPull {
		opts = append(opts, m.WithPullPolicy(m.PullPolicyAlways))
	}
	return opts, nil
}

// secretModifySpecs translates resolved secrets into modify entries keyed by
// env var name. Values are provided as host env references (MOTTE_SECRET_*),
// so the durable sandbox config stores no secret material.
func secretModifySpecs(desired []secrets.Spec) map[string]m.SecretModifySpec {
	specs := make(map[string]m.SecretModifySpec, len(desired))
	for _, secret := range desired {
		specs[secret.EnvVar] = m.SecretModifySpec{
			Env:          secrets.HostEnvVar(secret.EnvVar),
			AllowedHosts: secret.Allow,
			Substitution: &m.SecretSubstitution{HeaderFields: secret.HeaderFields},
		}
	}
	return specs
}

// networkConfig translates the merged network section.
// A non-empty allow list becomes deny-by-default egress with the entries as
// allow rules; no allow list keeps the runtime's default policy; and an
// explicitly empty allow list resolves to the default public profile, all
// like the CLI.
func networkConfig(n *profile.NetworkDoc) (*m.NetworkConfig, error) {
	var config *m.NetworkConfig
	switch {
	case n.Allow == nil:
		config = &m.NetworkConfig{}
	case len(*n.Allow) == 0:
		config = m.NetworkPolicy.FromProfiles(m.NetworkProfilePublic)
	default:
		rules := make([]m.PolicyRule, 0, len(*n.Allow))
		for _, entry := range *n.Allow {
			rule, err := policies.ParseAllowRule(entry)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
		config = &m.NetworkConfig{
			DefaultEgress:  m.PolicyActionDeny,
			DefaultIngress: m.PolicyActionAllow,
			Rules:          rules,
		}
	}
	if n.TLS != nil && n.TLS.Enabled != nil && *n.TLS.Enabled {
		// Enabled with the defaults: intercept port 443, verify upstream.
		config.TLS = &m.TLSConfig{}
	}
	return config, nil
}
