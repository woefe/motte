package main

import (
	"slices"
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// dnsRule is the expansion every plain dns entry shares.
var dnsRule = m.PolicyRule{
	Action:      m.PolicyActionAllow,
	Direction:   m.PolicyDirectionEgress,
	Destination: "host",
	Protocols:   []m.PolicyProtocol{m.PolicyProtocolUDP, m.PolicyProtocolTCP},
	Port:        "53",
}

// assertFindRule finds a rule by destination and, when ports is non-empty, by
// that port, then compares it field by field. The dns and host:tcp:9931
// entries both resolve to the `host` destination, so a port selects between
// them.
func assertFindRule(t *testing.T, rules []m.PolicyRule, want m.PolicyRule, ports string) {
	t.Helper()
	for _, got := range rules {
		if got.Destination != want.Destination {
			continue
		}
		if ports != "" && got.Port != ports && !slices.Contains(got.Ports, ports) {
			continue
		}
		assertRule(t, got, want)
		return
	}
	t.Fatalf("rules lack a %q entry (port %q)", want.Destination, ports)
}

// assertRule compares rules field by field; PolicyRule holds slices and
// is not comparable with ==.
func assertRule(t *testing.T, got, want m.PolicyRule) {
	t.Helper()
	if got.Action != want.Action || got.Direction != want.Direction || got.Destination != want.Destination {
		t.Errorf("rule = {action %v, direction %v, destination %q}, want {%v %v %q}",
			got.Action, got.Direction, got.Destination, want.Action, want.Direction, want.Destination)
	}
	if len(got.Protocols) != len(want.Protocols) {
		t.Fatalf("protocols = %v, want %v", got.Protocols, want.Protocols)
	}
	for i := range want.Protocols {
		if got.Protocols[i] != want.Protocols[i] {
			t.Errorf("protocols = %v, want %v", got.Protocols, want.Protocols)
		}
	}
	if got.Port != want.Port || len(got.Ports) != len(want.Ports) {
		t.Errorf("ports = {port %q, ports %v}, want {%q %v}", got.Port, got.Ports, want.Port, want.Ports)
	}
}

func TestParseAllowRule(t *testing.T) {
	allowEgress := func(destination string) *m.PolicyRule {
		return &m.PolicyRule{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: destination}
	}
	tests := []struct {
		entry  string
		want   *m.PolicyRule
		wantRe string // expected error substring
	}{
		{entry: "dns", want: &dnsRule},
		{entry: "dns:any", want: &dnsRule},
		{entry: "dns:any:53", want: &dnsRule},
		{entry: "dns:tcp", want: &m.PolicyRule{
			Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
			Destination: "host", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Port: "53",
		}},
		{entry: "dns:udp:5353", wantRe: "fixed to port 53"},
		{entry: "dns:sctp", wantRe: "supports"},
		{entry: "dns:x:y:z", wantRe: "trailing"},
		{
			entry: "*.github.com",
			want: &m.PolicyRule{
				Action:      m.PolicyActionAllow,
				Direction:   m.PolicyDirectionEgress,
				Destination: ".github.com",
			},
		},
		{
			entry: "go.dev",
			want: &m.PolicyRule{
				Action:      m.PolicyActionAllow,
				Direction:   m.PolicyDirectionEgress,
				Destination: "go.dev",
			},
		},
		{entry: "host:tcp:9931", want: &m.PolicyRule{
			Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
			Destination: "host", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Ports: []string{"9931"},
		}},
		{
			entry: "public",
			want: &m.PolicyRule{
				Action:      m.PolicyActionAllow,
				Direction:   m.PolicyDirectionEgress,
				Destination: "public",
			},
		},
		{
			entry: "meta",
			want: &m.PolicyRule{
				Action:      m.PolicyActionAllow,
				Direction:   m.PolicyDirectionEgress,
				Destination: "metadata",
			},
		},
		{
			entry: "any",
			want:  &m.PolicyRule{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: "*"},
		},
		{entry: "10.0.0.0/8", want: allowEgress("10.0.0.0/8")},
		{entry: "1.1.1.1", want: allowEgress("1.1.1.1")},
		{entry: "[2001:db8::1]", want: allowEgress("2001:db8::1")},
		{entry: "[2001:db8::/32]", want: allowEgress("2001:db8::/32")},
		{entry: "[2001:db8::1]:tcp:443", want: &m.PolicyRule{
			Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
			Destination: "2001:db8::1", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Ports: []string{"443"},
		}},
		{entry: "[192.168.0.1]", wantRe: "IPv6"},
		{entry: "[unclosed", wantRe: "unclosed"},
		{entry: "example.com:443", wantRe: "did you mean"},
		{entry: "public:tcp:99999", wantRe: "invalid port"},
		{entry: "public:tcp:443-80", wantRe: "lo must be <= hi"},
		{entry: "public:tcp:8000-9000", want: &m.PolicyRule{
			Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
			Destination: "public", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Ports: []string{"8000-9000"},
		}},
		{entry: "example.com:fast", wantRe: "not a recognized protocol"},
		{entry: "example:tcp", wantRe: "ambiguous"},
		{entry: "weird:host:tcp:53", wantRe: "trailing"},
	}
	for _, test := range tests {
		got, err := parseAllowRule(test.entry)
		if test.wantRe != "" {
			if err == nil || !strings.Contains(err.Error(), test.wantRe) {
				t.Errorf("parseAllowRule(%q) error = %v, want containing %q", test.entry, err, test.wantRe)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAllowRule(%q) = %v", test.entry, err)
			continue
		}
		assertRule(t, got, *test.want)
	}
}

func TestNetworkConfig(t *testing.T) {
	enabled := true
	allowList := []string{"dns", "*.github.com"}

	// No allow list: the runtime's default policy, with TLS when enabled.
	config, err := networkConfig(&networkDoc{TLS: &tlsDoc{Enabled: &enabled}})
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
	config, err = networkConfig(&networkDoc{Allow: &[]string{}})
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
	config, err = networkConfig(&networkDoc{Allow: &allowList, TLS: &tlsDoc{Enabled: &enabled}})
	if err != nil {
		t.Fatalf("networkConfig: %v", err)
	}
	if config.DefaultEgress != m.PolicyActionDeny || config.DefaultIngress != m.PolicyActionAllow {
		t.Errorf("defaults = %v/%v, want deny/allow", config.DefaultEgress, config.DefaultIngress)
	}
	if len(config.Rules) != 2 {
		t.Fatalf("rules = %+v, want 2", config.Rules)
	}
	assertRule(t, config.Rules[0], dnsRule)
	assertRule(t, config.Rules[1], m.PolicyRule{
		Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: ".github.com",
	})
	if config.TLS == nil {
		t.Error("TLS not set")
	}
}

// applyOptions folds sandbox options into a config, for assertions.
func applyOptions(opts []m.SandboxOption) m.SandboxConfig {
	config := m.SandboxConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	return config
}

func TestSandboxOptionsTranslateProfile(t *testing.T) {
	for name, image := range builtinImages() {
		t.Run(name, func(t *testing.T) {
			isolatedConfigDir(t)
			profile, err := loadProfile(name, fixtureEnv)
			if err != nil {
				t.Fatalf("loadProfile: %v", err)
			}
			opts, err := sandboxOptions(profile, false)
			if err != nil {
				t.Fatalf("sandboxOptions: %v", err)
			}
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

			if config.Network == nil || config.Network.DefaultEgress != m.PolicyActionDeny {
				t.Fatalf("Network = %+v", config.Network)
			}
			// One rule per allow entry, in declared order.
			if len(config.Network.Rules) != len(*profile.network.Allow) {
				t.Fatalf("Network.Rules = %d entries, want %d", len(config.Network.Rules), len(*profile.network.Allow))
			}
			// Spot-check the rule kinds every profile uses: the semantic dns
			// target, a domain suffix, and a host port.
			assertFindRule(t, config.Network.Rules, dnsRule, "53")
			assertFindRule(t, config.Network.Rules, m.PolicyRule{
				Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: ".github.com",
			}, "")
			assertFindRule(t, config.Network.Rules, m.PolicyRule{
				Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
				Destination: "host", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Ports: []string{"9931"},
			}, "9931")
			if config.Network.TLS == nil {
				t.Error("Network.TLS not enabled")
			}

			if len(config.Secrets) != 1 {
				t.Fatalf("Secrets = %+v, want 1", config.Secrets)
			}
			secret := config.Secrets[0]
			if secret.EnvVar != "OPENCODE_GO_KEY" || secret.Value != "sk_test" {
				t.Errorf("secret = %q/%q", secret.EnvVar, secret.Value)
			}
			if len(secret.Allow) != 1 || secret.Allow[0] != "*.opencode.ai" {
				t.Errorf("secret.Allow = %v", secret.Allow)
			}
			if len(secret.Substitution.HeaderFields) != 2 || secret.Substitution.HeaderFields[0] != "authorization" {
				t.Errorf("header fields = %v", secret.Substitution.HeaderFields)
			}
		})
	}
}

func TestSandboxOptionsNoPullKeepsDefaultPolicy(t *testing.T) {
	isolatedConfigDir(t)
	profile, err := loadProfile("golang", fixtureEnv)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	opts, err := sandboxOptions(profile, true)
	if err != nil {
		t.Fatalf("sandboxOptions: %v", err)
	}
	if got := applyOptions(opts).PullPolicy; got != m.PullPolicyDefault {
		t.Errorf("PullPolicy = %q, want the default (pull if missing)", got)
	}
}

// TestCreateProgressRenderingSanity checks the humanized rendering helpers.
func TestCreateProgressRenderingSanity(t *testing.T) {
	// Regression: pull events arrive with a layer count but no layer index yet.
	count := uint64(12)
	line := creationProgressLine(m.CreationProgress{
		Kind: "pull",
		Progress: m.CreationProgressDetail{
			Kind:       "layer_download_progress",
			Reference:  "ghcr.io/woefe/motte/golang:latest",
			LayerCount: &count,
		},
	})
	if want := "downloading 0 B"; line != want {
		t.Errorf("creationProgressLine = %q, want %q", line, want)
	}
	if got := humanBytes(1024); got != "1.0 KiB" {
		t.Errorf("humanBytes(1024) = %q", got)
	}
	if got := humanBytes(1024 * 1024); got != "1.0 MiB" {
		t.Errorf("humanBytes(1MiB) = %q", got)
	}
	if got := startupPhase("activating"); got != "activating sandbox" {
		t.Errorf("startupPhase = %q", got)
	}
	total := uint64(2048)
	if got := byteProgress(512, &total); got != "512 B / 2.0 KiB (25%)" {
		t.Errorf("byteProgress = %q", got)
	}
}
