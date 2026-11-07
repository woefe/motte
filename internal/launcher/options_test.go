package launcher

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
	motteconfig "github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/policies"
	"github.com/woefe/motte/internal/profile"
	"github.com/woefe/motte/internal/secrets"
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

// workingDir returns the test process's resolved working directory: the base
// the launcher resolves relative mount sources against.
func workingDir(t *testing.T) string {
	t.Helper()
	wd, err := motteconfig.ProjectPath()
	if err != nil {
		t.Fatalf("ProjectPath: %v", err)
	}
	return wd
}

func TestNetworkConfig(t *testing.T) {
	allowList := []string{"dns", "*.github.com"}

	// No allow list: the runtime's default policy, with TLS when enabled.
	config, err := networkConfig(&profile.NetworkDoc{TLS: &profile.TLSDoc{Enabled: true}})
	if err != nil {
		t.Fatalf("networkConfig: %v", err)
	}
	if len(config.Rules) != 0 {
		t.Errorf("rules = %v, want none", config.Rules)
	}
	if config.TLS == nil {
		t.Error("TLS not set")
	}

	// An explicit empty allow list resolves to the default public profile.
	config, err = networkConfig(&profile.NetworkDoc{Allow: []string{}})
	if err != nil {
		t.Fatalf("networkConfig: %v", err)
	}
	if config.DefaultEgress != m.PolicyActionDeny || config.DefaultIngress != m.PolicyActionAllow {
		t.Errorf("defaults = %v/%v, want deny/allow", config.DefaultEgress, config.DefaultIngress)
	}
	foundDNS, foundPublic := false, false
	for _, rule := range config.Rules {
		if rule.Destination == "host" && rule.Port == "53" {
			foundDNS = true
		}
		if rule.Destination == "public" {
			foundPublic = true
		}
	}
	if !foundDNS || !foundPublic {
		t.Errorf("rules = %+v, want the public profile's dns + public rules", config.Rules)
	}

	// A non-empty allow list is an egress allowlist with translated rules.
	config, err = networkConfig(&profile.NetworkDoc{Allow: allowList, TLS: &profile.TLSDoc{Enabled: true}})
	if err != nil {
		t.Fatalf("networkConfig: %v", err)
	}
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

func TestSandboxOptionsTranslateProfile(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	p, err := loadProfile("base")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	opts, err := sandboxOptions(p, false)
	if err != nil {
		t.Fatalf("sandboxOptions: %v", err)
	}
	config := applyOptions(opts)

	if config.Image != testutil.BuiltinImages()["base"] {
		t.Errorf("Image = %q, want %q", config.Image, testutil.BuiltinImages()["base"])
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
	// Replace is the launcher's call (--replace), not part of the profile.
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
	if mount.Kind() != m.MountKindBind || mount.Bind != workingDir(t) {
		t.Errorf("mount = %+v (bind %q), want a bind of the working directory", mount, mount.Bind)
	}
	if mount.Readonly {
		t.Error("mount is readonly, want rw")
	}

	opencodeDir, err := motteconfig.OpencodeDir()
	if err != nil {
		t.Fatal(err)
	}
	opencode, ok := config.Volumes["/etc/opencode"]
	if !ok {
		t.Fatalf("Volumes = %+v, want an /etc/opencode mount", config.Volumes)
	}
	if opencode.Kind() != m.MountKindBind || opencode.Bind != opencodeDir || !opencode.Readonly {
		t.Errorf("opencode mount = %+v (bind %q), want a readonly bind of %q",
			opencode, opencode.Bind, opencodeDir)
	}
	if _, err := os.Stat(filepath.Join(opencodeDir, "opencode.json")); err != nil {
		t.Errorf("default opencode.json: %v", err)
	}

	if config.Network == nil || config.Network.DefaultEgress != m.PolicyActionDeny {
		t.Fatalf("Network = %+v", config.Network)
	}
	// One rule per allow entry, in declared order.
	if len(config.Network.Rules) != len(p.Network.Allow) {
		t.Fatalf("Network.Rules = %d entries, want %d", len(config.Network.Rules), len(p.Network.Allow))
	}
	// Spot-check the rule kinds every profile uses: the semantic dns
	// target and domain suffixes.
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
	// The fingerprint of the effective policy rides in the labels, so
	// a reused VM can be told that its policy changed.
	if got := config.Labels[policies.LabelKey]; got != policies.Fingerprint(p) {
		t.Errorf("label %q = %q, want %q", policies.LabelKey, got, policies.Fingerprint(p))
	}

	// Secrets are never part of create options: values would persist
	// plaintext in the durable sandbox config on the host. They are
	// applied as post-create modify entries instead.
	if len(config.Secrets) != 0 {
		t.Fatalf("Secrets = %+v, want none", config.Secrets)
	}
}

func TestSandboxOptionsNoPullKeepsDefaultPolicy(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	p, err := loadProfile("golang")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	opts, err := sandboxOptions(p, true)
	if err != nil {
		t.Fatalf("sandboxOptions: %v", err)
	}
	if got := applyOptions(opts).PullPolicy; got != m.PullPolicyDefault {
		t.Errorf("PullPolicy = %q, want the default (pull if missing)", got)
	}
}

// TestSecretModifySpecs builds modify entries with env references only.
func TestSecretModifySpecs(t *testing.T) {
	specs := secretModifySpecs([]secrets.Spec{
		{EnvVar: "a_key", Allow: []string{"a.example.com"}, HeaderFields: []string{"authorization"}},
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
