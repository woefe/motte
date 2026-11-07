// Translation of a resolved project into microsandbox Go SDK options.
package launcher

import (
	msb "github.com/superradcompany/microsandbox/sdk/go"
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
func sandboxOptions(resolved project.Resolved, noPull bool) []msb.SandboxOption {
	opts := []msb.SandboxOption{
		msb.WithImage(resolved.Image),
		msb.WithCPUs(4),
		msb.WithMemory(4096),
		msb.WithWorkdir("/workspace"),
		msb.WithShell("/bin/bash"),
		msb.WithUser("motte"),
		msb.WithMounts(map[string]msb.MountConfig{
			"/workspace": msb.Mount.Bind(resolved.WorkspaceDir, msb.MountOptions{}),
			"/etc/opencode": msb.Mount.Bind(resolved.OpencodeDir, msb.MountOptions{
				Readonly: true,
				Nosuid:   true,
				Nodev:    true,
			}),
		}),
		msb.WithCmd("opencode"),
		msb.WithScripts(map[string]string{
			"check": "opencode --version",
		}),
		msb.WithNetwork(networkConfig(resolved.Rules)),
		msb.WithLabels(map[string]string{labelKey: resolved.Fingerprint}),
	}
	// Secrets are deliberately absent here: create-time raw values persist
	// plaintext in the durable sandbox config on the host. Secrets are
	// applied after creation instead, as env-source modify entries — see
	// convergeAfterCreate and secretModifySpecs.
	if !noPull {
		opts = append(opts, msb.WithPullPolicy(msb.PullPolicyAlways))
	}
	return opts
}

// secretModifySpecs translates resolved secrets into modify entries keyed by
// env var name. Values are provided as host env references (MOTTE_SECRET_*),
// so the durable sandbox config stores no secret material.
func secretModifySpecs(desired []project.ResolvedSecret) map[string]msb.SecretModifySpec {
	specs := make(map[string]msb.SecretModifySpec, len(desired))
	for _, secret := range desired {
		specs[secret.EnvVar] = msb.SecretModifySpec{
			Env:          secret.HostEnv,
			AllowedHosts: secret.Allow,
			Substitution: &msb.SecretSubstitution{HeaderFields: secret.HeaderFields},
		}
	}
	return specs
}

// networkConfig wraps the project's egress allow rules into a deny-by-default
// egress NetworkConfig with TLS interception enabled.
func networkConfig(rules []msb.PolicyRule) *msb.NetworkConfig {
	return &msb.NetworkConfig{
		DefaultEgress:  msb.PolicyActionDeny,
		DefaultIngress: msb.PolicyActionAllow,
		Rules:          rules,
		TLS:            &msb.TLSConfig{},
	}
}
