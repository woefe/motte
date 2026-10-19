// Translation of a merged profile into microsandbox Go SDK options.
//
// The translations mirror how the msb CLI resolves the same YAML values
// (crates/cli of the microsandbox sources): sizes are GiB/MiB-based, network
// allow entries follow the rule-target grammar TARGET[:PROTO[:PORTS]] with a
// non-empty allow list implying deny-by-default egress, and `network.tls.
// enabled: true` turns on TLS interception with its defaults.
package main

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

// sandboxOptions translates a profile into the options for creating the
// motte-<profile> sandbox.
// With noPull set it leaves the image pull policy at the runtime default (pull
// only if missing) so a locally loaded image wins; otherwise it mirrors the
// old `msb pull` by always refreshing the image.
func sandboxOptions(p *profile, noPull bool) ([]m.SandboxOption, error) {
	opts := []m.SandboxOption{
		m.WithImage(p.image),
		m.WithReplace(), // replace any existing motte-<profile> sandbox
	}
	if p.cpus != nil {
		opts = append(opts, m.WithCPUs(*p.cpus))
	}
	if p.memoryMiB != nil {
		opts = append(opts, m.WithMemory(*p.memoryMiB))
	}
	if p.workdir != nil {
		opts = append(opts, m.WithWorkdir(*p.workdir))
	}
	if p.shell != nil {
		opts = append(opts, m.WithShell(*p.shell))
	}
	if len(p.mounts) > 0 {
		mounts := make(map[string]m.MountConfig, len(p.mounts))
		for _, mount := range p.mounts {
			mounts[mount.guestPath] = m.Mount.Bind(mount.hostPath, m.MountOptions{
				Readonly: mount.readonly,
				Noexec:   mount.noexec,
				Nosuid:   mount.nosuid,
				Nodev:    mount.nodev,
			})
		}
		opts = append(opts, m.WithMounts(mounts))
	}
	if p.cmd != nil {
		opts = append(opts, m.WithCmd(p.cmd...))
	}
	if len(p.scripts) > 0 {
		opts = append(opts, m.WithScripts(p.scripts))
	}
	if p.network != nil {
		network, err := networkConfig(p.network)
		if err != nil {
			return nil, err
		}
		opts = append(opts, m.WithNetwork(network))
	}
	if len(p.secrets) > 0 {
		entries := make([]m.SecretEntry, 0, len(p.secrets))
		for _, secret := range p.secrets {
			entries = append(entries, m.Secret.Env(secret.envVar, secret.value, m.SecretEnvOptions{
				Allow: secret.allow,
				Substitution: m.SecretSubstitution{
					HeaderFields: secret.headerFields,
				},
			}))
		}
		opts = append(opts, m.WithSecrets(entries...))
	}
	if !noPull {
		opts = append(opts, m.WithPullPolicy(m.PullPolicyAlways))
	}
	return opts, nil
}

// networkConfig translates the merged network section.
// A non-empty allow list becomes deny-by-default egress with the entries as
// allow rules; no allow list keeps the runtime's default policy; and an
// explicitly empty allow list resolves to the default public profile, all
// like the CLI.
func networkConfig(n *networkDoc) (*m.NetworkConfig, error) {
	var config *m.NetworkConfig
	switch {
	case n.Allow == nil:
		config = &m.NetworkConfig{}
	case len(*n.Allow) == 0:
		config = m.NetworkPolicy.FromProfiles(m.NetworkProfilePublic)
	default:
		rules := make([]m.PolicyRule, 0, len(*n.Allow))
		for _, entry := range *n.Allow {
			rule, err := parseAllowRule(entry)
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

// parseAllowRule translates one network.allow entry, the CLI rule-target
// grammar TARGET[:PROTO[:PORTS]], into an egress allow rule.
// IPv6 addresses and CIDRs must be wrapped in [...] so their colons do not
// collide with the field separator.
func parseAllowRule(entry string) (m.PolicyRule, error) {
	rule := m.PolicyRule{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress}
	if entry == "dns" || strings.HasPrefix(entry, "dns:") {
		return parseDNSRule(entry)
	}

	var target, proto, ports string
	protoPresent := false
	if strings.HasPrefix(entry, "[") {
		rest := entry[1:]
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return rule, fmt.Errorf("network rule %q: unclosed `[`; IPv6 targets must be wrapped as [<addr>]", entry)
		}
		target = entry[:end+2]
		after := rest[end+1:]
		if after != "" {
			if !strings.HasPrefix(after, ":") {
				return rule, fmt.Errorf("network rule %q: unexpected content after `]`", entry)
			}
			fields := strings.Split(after[1:], ":")
			if len(fields) > 2 {
				return rule, trailingJunkError(entry)
			}
			proto, protoPresent, ports = fields[0], true, ""
			if len(fields) == 2 {
				ports = fields[1]
			}
		}
	} else {
		fields := strings.Split(entry, ":")
		if len(fields) > 3 {
			return rule, trailingJunkError(entry)
		}
		target = fields[0]
		if len(fields) >= 2 {
			proto, protoPresent = fields[1], true
		}
		if len(fields) == 3 {
			ports = fields[2]
		}
	}
	if looksLikePort(proto) {
		return rule, fmt.Errorf("network rule %q: %q is a port, not a protocol; did you mean %s:tcp:%s?", entry, proto, target, proto)
	}
	destination, err := parseRuleTarget(target)
	if err != nil {
		return rule, fmt.Errorf("network rule %q: %w", entry, err)
	}
	rule.Destination = destination
	if rule.Protocols, err = parseRuleProtocols(proto, protoPresent); err != nil {
		return rule, fmt.Errorf("network rule %q: %w", entry, err)
	}
	if rule.Ports, err = parseRulePorts(ports); err != nil {
		return rule, fmt.Errorf("network rule %q: %w", entry, err)
	}
	return rule, nil
}

// parseDNSRule expands the semantic dns target into the gateway TCP/UDP
// port-53 rule, fixed to egress like the CLI.
func parseDNSRule(entry string) (m.PolicyRule, error) {
	rule := m.PolicyRule{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: "host"}
	fields := strings.Split(entry, ":")
	if len(fields) > 3 {
		return rule, trailingJunkError(entry)
	}
	switch len(fields) {
	case 2, 3:
		switch fields[1] {
		case "", "any":
			rule.Protocols = []m.PolicyProtocol{m.PolicyProtocolUDP, m.PolicyProtocolTCP}
		case "udp":
			rule.Protocols = []m.PolicyProtocol{m.PolicyProtocolUDP}
		case "tcp":
			rule.Protocols = []m.PolicyProtocol{m.PolicyProtocolTCP}
		default:
			return rule, fmt.Errorf("network rule %q: the `dns` target supports `tcp`, `udp`, or `any`, not %q", entry, fields[1])
		}
		if len(fields) == 3 {
			switch fields[2] {
			case "", "any", "53":
			default:
				return rule, fmt.Errorf("network rule %q: the `dns` target is fixed to port 53; omit the port or use `53`/`any`", entry)
			}
		}
	case 1:
		rule.Protocols = []m.PolicyProtocol{m.PolicyProtocolUDP, m.PolicyProtocolTCP}
	}
	rule.Port = "53"
	return rule, nil
}

// parseRuleTarget resolves a rule target into the SDK destination string:
// a group keyword, an IP or CIDR, an exact domain, a domain suffix (Go's
// ".suffix" form), "*", or one of the *.name / suffix= / domain= spellings.
func parseRuleTarget(raw string) (string, error) {
	if strings.HasPrefix(raw, "[") {
		if !strings.HasSuffix(raw, "]") {
			return "", fmt.Errorf("unclosed `[`")
		}
		inner := raw[1 : len(raw)-1]
		if strings.Contains(inner, "/") {
			if _, network, err := net.ParseCIDR(inner); err != nil || network.IP.To4() != nil {
				return "", fmt.Errorf("%q is not an IPv6 CIDR; only IPv6 forms belong inside [...]", inner)
			}
			return inner, nil
		}
		if ip := net.ParseIP(inner); ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("%q is not an IPv6 address; only IPv6 forms belong inside [...]", inner)
		}
		return inner, nil
	}
	switch raw {
	case "":
		return "", fmt.Errorf("empty target")
	case "any":
		return "*", nil
	case "public", "private", "loopback", "link-local", "multicast", "host":
		return raw, nil
	case "meta":
		// The CLI spells the metadata group `meta`; the SDK uses `metadata`.
		return "metadata", nil
	}
	if rest, ok := strings.CutPrefix(raw, "*."); ok {
		return "." + rest, nil
	}
	if rest, ok := strings.CutPrefix(raw, "suffix="); ok {
		return "." + rest, nil
	}
	if rest, ok := strings.CutPrefix(raw, "domain="); ok {
		return rest, nil
	}
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return "", fmt.Errorf("invalid CIDR %q", raw)
		}
		return raw, nil
	}
	if net.ParseIP(raw) != nil {
		return raw, nil // the SDK turns a bare IP into a single-host CIDR
	}
	if strings.Contains(raw, ".") {
		return raw, nil
	}
	return "", fmt.Errorf("%q is ambiguous (a single-label hostname or a keyword typo); use domain=%s", raw, raw)
}

// parseRuleProtocols resolves the protocol field; an empty set matches any
// protocol.
func parseRuleProtocols(proto string, present bool) ([]m.PolicyProtocol, error) {
	if !present || proto == "any" {
		return nil, nil
	}
	switch proto {
	case "tcp":
		return []m.PolicyProtocol{m.PolicyProtocolTCP}, nil
	case "udp":
		return []m.PolicyProtocol{m.PolicyProtocolUDP}, nil
	case "icmpv4":
		return []m.PolicyProtocol{m.PolicyProtocolICMPv4}, nil
	case "icmpv6":
		return []m.PolicyProtocol{m.PolicyProtocolICMPv6}, nil
	default:
		return nil, fmt.Errorf("%q is not a recognized protocol; expected `any`, `tcp`, `udp`, `icmpv4`, or `icmpv6`", proto)
	}
}

// parseRulePorts resolves the ports field; an empty set matches any port.
func parseRulePorts(ports string) ([]string, error) {
	switch ports {
	case "":
		return nil, nil
	case "any":
		return nil, nil
	}
	if lo, hi, ok := strings.Cut(ports, "-"); ok {
		loPort, err := parsePort(lo)
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", ports)
		}
		hiPort, err := parsePort(hi)
		if err != nil || loPort > hiPort {
			return nil, fmt.Errorf("invalid port range %q; lo must be <= hi", ports)
		}
		return []string{ports}, nil
	}
	if _, err := parsePort(ports); err != nil {
		return nil, fmt.Errorf("invalid port %q; expected a port or a lo-hi range", ports)
	}
	return []string{ports}, nil
}

// parsePort parses one uint16 port.
func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	return uint16(port), err
}

// looksLikePort reports whether a protocol-slot value looks like a port
// number, the URL-style `host:port` typo the CLI calls out.
func looksLikePort(s string) bool {
	if s == "" {
		return false
	}
	if _, err := strconv.ParseUint(s, 10, 16); err == nil {
		return true
	}
	lo, hi, ok := strings.Cut(s, "-")
	return ok && lo != "" && hi != "" && parseableU16(lo) && parseableU16(hi)
}

func parseableU16(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

func trailingJunkError(entry string) error {
	return fmt.Errorf("network rule %q has trailing fields after the ports; if this is an IPv6 address, wrap it as [<addr>]", entry)
}

// parseSizeMiB parses a CLI size string into MiB: bare numbers are MiB, M is
// MiB, and G (also fractional, like 1.5G) is GiB.
func parseSizeMiB(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if n, ok := cutAnySuffix(s, "G", "g"); ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size: %w", err)
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return 0, fmt.Errorf("size must be a finite positive number")
		}
		mib := value * 1024
		if mib > math.MaxUint32 {
			return 0, fmt.Errorf("size too large")
		}
		return uint32(mib), nil
	}
	if n, ok := cutAnySuffix(s, "M", "m"); ok {
		value, err := strconv.ParseUint(strings.TrimSpace(n), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid size: %w", err)
		}
		return uint32(value), nil
	}
	value, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid size (expected e.g. 512M, 1G): %w", err)
	}
	return uint32(value), nil
}

// cutAnySuffix strips either suffix from s.
func cutAnySuffix(s, suffix1, suffix2 string) (string, bool) {
	if rest, ok := strings.CutSuffix(s, suffix1); ok {
		return rest, true
	}
	return strings.CutSuffix(s, suffix2)
}
