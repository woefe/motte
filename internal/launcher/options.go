// Translation of a project's image and effective allow list into microsandbox
// Go SDK options.
package launcher

import (
	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/secrets"
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
func sandboxOptions(image string, allow []string, noPull bool) ([]m.SandboxOption, error) {
	projectDir, err := config.ProjectPath()
	if err != nil {
		return nil, err
	}
	opencodeDir, err := config.EnsureOpencodeConfig()
	if err != nil {
		return nil, err
	}
	network, err := networkConfig(allow)
	if err != nil {
		return nil, err
	}
	opts := []m.SandboxOption{
		m.WithImage(image),
		m.WithCPUs(4),
		m.WithMemory(4096),
		m.WithWorkdir("/workspace"),
		m.WithShell("/bin/bash"),
		m.WithUser("motte"),
		m.WithMounts(map[string]m.MountConfig{
			"/workspace": m.Mount.Bind(projectDir, m.MountOptions{}),
			"/etc/opencode": m.Mount.Bind(opencodeDir, m.MountOptions{
				Readonly: true,
				Nosuid:   true,
				Nodev:    true,
			}),
		}),
		m.WithCmd("opencode"),
		m.WithScripts(map[string]string{
			"check": "opencode --version",
		}),
		m.WithNetwork(network),
		m.WithLabels(map[string]string{policies.LabelKey: policies.Fingerprint(image, allow)}),
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

// networkConfig translates the effective allow list into a deny-by-default
// egress NetworkConfig with TLS interception enabled.
func networkConfig(allow []string) (*m.NetworkConfig, error) {
	rules := make([]m.PolicyRule, 0, len(allow))
	for _, entry := range allow {
		rule, err := policies.ParseAllowRule(entry)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return &m.NetworkConfig{
		DefaultEgress:  m.PolicyActionDeny,
		DefaultIngress: m.PolicyActionAllow,
		Rules:          rules,
		TLS:            &m.TLSConfig{},
	}, nil
}
