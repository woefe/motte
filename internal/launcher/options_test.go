package launcher

import (
	"slices"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/project"
	"github.com/woefe/motte/internal/testutil"
)

// assertFindRule finds a rule by destination and, when ports is non-empty, by
// that port, then compares it field by field.
func assertFindRule(t *testing.T, rules []m.PolicyRule, want m.PolicyRule, ports string) {
	t.Helper()
	for _, got := range rules {
		if got.Destination != want.Destination {
			continue
		}
		if ports != "" && got.Port != ports && !slices.Contains(got.Ports, ports) {
			continue
		}
		testutil.AssertRule(t, got, want)
		return
	}
	t.Fatalf("rules lack a %q entry (port %q)", want.Destination, ports)
}

// applyOptions folds sandbox options into a config, for assertions.
func applyOptions(opts []m.SandboxOption) m.SandboxConfig {
	config := m.SandboxConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	return config
}

func TestNetworkConfig(t *testing.T) {
	rules, err := project.ParseRules([]string{"dns", "*.github.com"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	config := networkConfig(rules)
	if config.DefaultEgress != m.PolicyActionDeny || config.DefaultIngress != m.PolicyActionAllow {
		t.Errorf("defaults = %v/%v, want deny/allow", config.DefaultEgress, config.DefaultIngress)
	}
	if len(config.Rules) != 2 {
		t.Fatalf("rules = %+v, want 2", config.Rules)
	}
	testutil.AssertRule(t, config.Rules[0], testutil.DNSRule)
	testutil.AssertRule(t, config.Rules[1], m.PolicyRule{
		Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: ".github.com",
	})
	if config.TLS == nil {
		t.Error("TLS not set")
	}
}

func TestSandboxOptions(t *testing.T) {
	image := testutil.BuiltinImages()["base"]
	allow := []string{"dns", "*.github.com", "*.opencode.ai"}
	rules, err := project.ParseRules(allow)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	resolved := project.Resolved{
		SandboxName:  "motte-1234567890ab",
		Image:        image,
		WorkspaceDir: "/host/workspace",
		OpencodeDir:  "/host/opencode",
		Rules:        rules,
		Fingerprint:  project.Fingerprint(image, allow),
	}
	opts := sandboxOptions(resolved, false)
	config := applyOptions(opts)

	if config.Image != image {
		t.Errorf("Image = %q, want %q", config.Image, image)
	}
	if config.CPUs != 4 || config.MemoryMiB != 4096 {
		t.Errorf("CPUs/Memory = %d/%d", config.CPUs, config.MemoryMiB)
	}
	if config.Workdir != "/workspace" || config.Shell != "/bin/bash" {
		t.Errorf("Workdir/Shell = %q/%q", config.Workdir, config.Shell)
	}
	if config.User != "motte" {
		t.Errorf("User = %q, want %q", config.User, "motte")
	}
	if len(config.Cmd) != 1 || config.Cmd[0] != "opencode" {
		t.Errorf("Cmd = %v", config.Cmd)
	}
	// Replace is the launcher's call (--replace), not set by sandboxOptions.
	if config.Replace {
		t.Error("Replace should be left unset by sandboxOptions")
	}
	if config.PullPolicy != m.PullPolicyAlways {
		t.Errorf("PullPolicy = %q, want always", config.PullPolicy)
	}
	if got, ok := config.Scripts["check"]; !ok || !strings.Contains(got, "opencode --version") {
		t.Errorf("Scripts.check = %q", got)
	}

	mount, ok := config.Volumes["/workspace"]
	if !ok {
		t.Fatalf("Volumes = %+v, want a /workspace mount", config.Volumes)
	}
	if mount.Kind() != m.MountKindBind || mount.Bind != "/host/workspace" {
		t.Errorf("mount = %+v (bind %q), want a bind of /host/workspace", mount, mount.Bind)
	}
	if mount.Readonly {
		t.Error("mount is readonly, want rw")
	}

	opencode, ok := config.Volumes["/etc/opencode"]
	if !ok {
		t.Fatalf("Volumes = %+v, want an /etc/opencode mount", config.Volumes)
	}
	if opencode.Kind() != m.MountKindBind || opencode.Bind != "/host/opencode" || !opencode.Readonly {
		t.Errorf("opencode mount = %+v (bind %q), want a readonly bind of /host/opencode",
			opencode, opencode.Bind)
	}

	if config.Network == nil || config.Network.DefaultEgress != m.PolicyActionDeny {
		t.Fatalf("Network = %+v", config.Network)
	}
	// One rule per allow entry, in declared order.
	if len(config.Network.Rules) != len(allow) {
		t.Fatalf("Network.Rules = %d entries, want %d", len(config.Network.Rules), len(allow))
	}
	assertFindRule(t, config.Network.Rules, testutil.DNSRule, "53")
	assertFindRule(t, config.Network.Rules, m.PolicyRule{
		Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: ".github.com",
	}, "")
	assertFindRule(t, config.Network.Rules, m.PolicyRule{
		Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: ".opencode.ai",
	}, "")
	if config.Network.TLS == nil {
		t.Error("Network.TLS not enabled")
	}
	// The fingerprint of the image and effective policy rides in the labels,
	// so a reused VM can be told that its config changed.
	if got := config.Labels[labelKey]; got != resolved.Fingerprint {
		t.Errorf("label %q = %q, want %q", labelKey, got, resolved.Fingerprint)
	}

	// Secrets are never part of create options: values would persist
	// plaintext in the durable sandbox config on the host. They are
	// applied as post-create modify entries instead.
	if len(config.Secrets) != 0 {
		t.Fatalf("Secrets = %+v, want none", config.Secrets)
	}
}

func TestSandboxOptionsNoPullKeepsDefaultPolicy(t *testing.T) {
	opts := sandboxOptions(project.Resolved{Image: testutil.BuiltinImages()["golang"]}, true)
	if got := applyOptions(opts).PullPolicy; got != m.PullPolicyDefault {
		t.Errorf("PullPolicy = %q, want the default (pull if missing)", got)
	}
}

// TestSecretModifySpecs builds modify entries with env references only.
func TestSecretModifySpecs(t *testing.T) {
	specs := secretModifySpecs([]project.ResolvedSecret{
		{
			EnvVar:       "a_key",
			HostEnv:      "MOTTE_SECRET_a_key",
			Allow:        []string{"a.example.com"},
			HeaderFields: []string{"authorization"},
		},
	})
	spec, ok := specs["a_key"]
	if !ok {
		t.Fatalf("specs = %+v, want a_key", specs)
	}
	if spec.Env != "MOTTE_SECRET_a_key" || spec.Value != "" || spec.Store != "" {
		t.Errorf("spec = %+v, want env-only material", spec)
	}
	if len(spec.AllowedHosts) != 1 || spec.AllowedHosts[0] != "a.example.com" {
		t.Errorf("AllowedHosts = %v", spec.AllowedHosts)
	}
	if spec.Substitution == nil || len(spec.Substitution.HeaderFields) != 1 {
		t.Errorf("Substitution = %+v", spec.Substitution)
	}
	if none := secretModifySpecs(nil); len(none) != 0 {
		t.Errorf("nil input produced %+v", none)
	}
}
