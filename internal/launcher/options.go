// Translation of a resolved project into microsandbox Go SDK options.
package launcher

import (
	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/project"
)

// sandboxOptions builds the options for creating a project's sandbox: 4 CPUs,
// 4 GiB memory, the current working directory mounted at /workspace, the user's
// OpenCode config directory mounted read-only at /etc/opencode, deny-by-default
// egress with allow rules and TLS interception enabled, and the `opencode`
// workload.
//
// Replacing an existing VM is the launcher's call (see --replace), so no
// replace option is set here. With noPull set it leaves the image pull policy
// at the runtime default (pull only if missing) so a locally loaded image wins;
// otherwise it always refreshes the image.
func sandboxOptions(resolved project.Resolved, noPull bool) []m.SandboxOption {
	opts := []m.SandboxOption{
		m.WithImage(resolved.Image),
		m.WithCPUs(4),
		m.WithMemory(4096),
		m.WithWorkdir("/workspace"),
		m.WithShell("/bin/bash"),
		m.WithUser("motte"),
		m.WithMounts(map[string]m.MountConfig{
			"/workspace": m.Mount.Bind(resolved.WorkspaceDir, m.MountOptions{}),
			"/etc/opencode": m.Mount.Bind(resolved.OpencodeDir, m.MountOptions{
				Readonly: true,
				Nosuid:   true,
				Nodev:    true,
			}),
		}),
		m.WithCmd("opencode"),
		m.WithScripts(map[string]string{
			"check": "opencode --version",
		}),
		m.WithNetwork(networkConfig(resolved.Rules)),
		m.WithLabels(map[string]string{labelKey: resolved.Fingerprint}),
	}
	// Secrets are deliberately absent here: create-time raw values persist
	// plaintext in the durable sandbox config on the host. Secrets are
	// applied after creation instead, as env-source modify entries — see
	// convergeAfterCreate and secretModifySpecs.
	if !noPull {
		opts = append(opts, m.WithPullPolicy(m.PullPolicyAlways))
	}
	return opts
}

// secretModifySpecs translates resolved secrets into modify entries keyed by
// env var name. Values are provided as host env references (MOTTE_SECRET_*),
// so the durable sandbox config stores no secret material.
func secretModifySpecs(desired []project.ResolvedSecret) map[string]m.SecretModifySpec {
	specs := make(map[string]m.SecretModifySpec, len(desired))
	for _, secret := range desired {
		specs[secret.EnvVar] = m.SecretModifySpec{
			Env:          secret.HostEnv,
			AllowedHosts: secret.Allow,
			Substitution: &m.SecretSubstitution{HeaderFields: secret.HeaderFields},
		}
	}
	return specs
}

// networkConfig wraps the project's egress allow rules into a deny-by-default
// egress NetworkConfig with TLS interception enabled.
func networkConfig(rules []m.PolicyRule) *m.NetworkConfig {
	return &m.NetworkConfig{
		DefaultEgress:  m.PolicyActionDeny,
		DefaultIngress: m.PolicyActionAllow,
		Rules:          rules,
		TLS:            &m.TLSConfig{},
	}
}
