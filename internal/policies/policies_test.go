package policies

import (
	"strings"
	"testing"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/config"
	"github.com/woefe/motte/internal/testutil"
)

// mustDirHash returns the hash of the current directory.
func mustDirHash(t *testing.T) string {
	t.Helper()
	hash, err := config.DirHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// TestTemplate covers the scope-file skeletons: the entry comments, and the
// project path only for the current directory's project scope.
func TestTemplate(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	global, err := Template(config.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(global, "network:") || !strings.Contains(global, "rule grammar") {
		t.Errorf("global template = %q, want the entry comments", global)
	}
	project, err := Template(config.Scope{Hash: mustDirHash(t)})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := config.ProjectPath()
	if err != nil {
		t.Fatalf("ProjectPath: %v", err)
	}
	if !strings.Contains(project, "Project path: "+dir) {
		t.Errorf("project template = %q, want the current directory's path", project)
	}
	foreign, err := Template(config.Scope{Hash: "1234567890ab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(foreign, "Project path:") {
		t.Errorf("foreign template = %q, want no project path", foreign)
	}
}

// TestParseAllowRule covers the CLI rule grammar: the semantic dns target,
// groups, wildcards, IPs and CIDRs, protocols, ports, and the error hints.
func TestParseAllowRule(t *testing.T) {
	allowEgress := func(destination string) *m.PolicyRule {
		return &m.PolicyRule{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: destination}
	}
	allowTCP := func(destination string, ports ...string) *m.PolicyRule {
		rule := allowEgress(destination)
		rule.Protocols = []m.PolicyProtocol{m.PolicyProtocolTCP}
		rule.Ports = ports
		return rule
	}
	tests := []struct {
		entry  string
		want   *m.PolicyRule
		wantRe string // expected error substring
	}{
		{entry: "dns", want: &testutil.DNSRule},
		{entry: "dns:any", want: &testutil.DNSRule},
		{entry: "dns:any:53", want: &testutil.DNSRule},
		{entry: "dns:tcp", want: &m.PolicyRule{
			Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress,
			Destination: "host", Protocols: []m.PolicyProtocol{m.PolicyProtocolTCP}, Port: "53",
		}},
		{entry: "dns:udp:5353", wantRe: "fixed to port 53"},
		{entry: "dns:sctp", wantRe: "supports"},
		{entry: "dns:x:y:z", wantRe: "trailing"},
		{entry: "*.github.com", want: allowEgress(".github.com")},
		{entry: "go.dev", want: allowEgress("go.dev")},
		{entry: "host:tcp:9931", want: allowTCP("host", "9931")},
		{entry: "public", want: allowEgress("public")},
		{entry: "meta", want: allowEgress("metadata")},
		{entry: "any", want: allowEgress("*")},
		{entry: "10.0.0.0/8", want: allowEgress("10.0.0.0/8")},
		{entry: "1.1.1.1", want: allowEgress("1.1.1.1")},
		{entry: "[2001:db8::1]", want: allowEgress("2001:db8::1")},
		{entry: "[2001:db8::/32]", want: allowEgress("2001:db8::/32")},
		{entry: "[2001:db8::1]:tcp:443", want: allowTCP("2001:db8::1", "443")},
		{entry: "[192.168.0.1]", wantRe: "IPv6"},
		{entry: "[unclosed", wantRe: "unclosed"},
		{entry: "example.com:443", wantRe: "did you mean"},
		{entry: "public:tcp:99999", wantRe: "invalid port"},
		{entry: "public:tcp:443-80", wantRe: "lo must be <= hi"},
		{entry: "public:tcp:8000-9000", want: allowTCP("public", "8000-9000")},
		{entry: "example.com:fast", wantRe: "not a recognized protocol"},
		{entry: "example:tcp", wantRe: "ambiguous"},
		{entry: "weird:host:tcp:53", wantRe: "trailing"},
	}
	for _, test := range tests {
		got, err := ParseAllowRule(test.entry)
		if test.wantRe != "" {
			if err == nil || !strings.Contains(err.Error(), test.wantRe) {
				t.Errorf("ParseAllowRule(%q) error = %v, want containing %q", test.entry, err, test.wantRe)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAllowRule(%q) = %v", test.entry, err)
			continue
		}
		testutil.AssertRule(t, got, *test.want)
	}
}
