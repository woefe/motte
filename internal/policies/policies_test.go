package policies

import (
	"errors"
	"slices"
	"strings"
	"testing"

	msb "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/woefe/motte/internal/testutil"
)

// TestExtendAllow checks that ExtendAllow deduplicates entries while preserving
// order.
func TestExtendAllow(t *testing.T) {
	initial := []string{"dns", "*.github.com"}
	extended := ExtendAllow(initial, []string{"*.github.com", "extra.example.com"})
	testutil.AssertAllowUnique(t, extended)
	want := []string{"dns", "*.github.com", "extra.example.com"}
	if !slices.Equal(extended, want) {
		t.Errorf("extended = %v, want %v", extended, want)
	}
}

// TestValidateGroupName checks the slug rule for policy group names.
func TestValidateGroupName(t *testing.T) {
	for _, ok := range []string{"work-vpn", "golang", "corp1", "a-b-c"} {
		if err := ValidateGroupName(ok); err != nil {
			t.Errorf("ValidateGroupName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Work", "work_vpn", "-work", "work-", "work--vpn", "a/b", ".."} {
		if err := ValidateGroupName(bad); err == nil {
			t.Errorf("ValidateGroupName(%q) = nil, want an error", bad)
		}
	}
}

// TestTemplateAndReadGroup covers the policy group skeleton and strict reading.
func TestTemplateAndReadGroup(t *testing.T) {
	testutil.IsolatedConfigDir(t)
	tmpl, err := Template("work-vpn")
	if err != nil {
		t.Fatalf("Template: %v", err)
	}
	if !strings.Contains(tmpl, "# motte policy group — work-vpn") || !strings.Contains(tmpl, "allow:") {
		t.Errorf("Template = %q, want header and allow:", tmpl)
	}
	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", tmpl)
	entries, err := ReadGroup("work-vpn")
	if err != nil || len(entries) != 0 {
		t.Fatalf("ReadGroup(template) = %v, %v; want empty without error", entries, err)
	}

	testutil.WriteConfigFile(t, "policies/work-vpn.yaml", "allow:\n  - \"*.corp.example.com\"\n")
	entries, err = ReadGroup("work-vpn")
	if err != nil || len(entries) != 1 || entries[0] != "*.corp.example.com" {
		t.Fatalf("ReadGroup = %v, %v", entries, err)
	}

	if _, err := ReadGroup("missing"); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("ReadGroup(missing) = %v, want ErrGroupNotFound", err)
	}
}

// TestParseAllowRule covers the CLI rule grammar: the semantic dns target,
// groups, wildcards, IPs and CIDRs, protocols, ports, and the error hints.
func TestParseAllowRule(t *testing.T) {
	allowEgress := func(destination string) *msb.PolicyRule {
		return &msb.PolicyRule{
			Action:      msb.PolicyActionAllow,
			Direction:   msb.PolicyDirectionEgress,
			Destination: destination,
		}
	}
	allowTCP := func(destination string, ports ...string) *msb.PolicyRule {
		rule := allowEgress(destination)
		rule.Protocols = []msb.PolicyProtocol{msb.PolicyProtocolTCP}
		rule.Ports = ports
		return rule
	}
	tests := []struct {
		entry  string
		want   *msb.PolicyRule
		wantRe string // expected error substring
	}{
		{entry: "dns", want: &testutil.DNSRule},
		{entry: "dns:any", want: &testutil.DNSRule},
		{entry: "dns:any:53", want: &testutil.DNSRule},
		{entry: "dns:tcp", want: &msb.PolicyRule{
			Action: msb.PolicyActionAllow, Direction: msb.PolicyDirectionEgress,
			Destination: "host", Protocols: []msb.PolicyProtocol{msb.PolicyProtocolTCP}, Port: "53",
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
