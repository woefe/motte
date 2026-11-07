// The network rule grammar: entries of the form TARGET[:PROTO[:PORTS]], the
// same grammar the microsandbox CLI accepts, translated into SDK policy
// rules. IPv6 addresses and CIDRs must be wrapped in [...] so their colons do
// not collide with the field separator.
package policies

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

// ParseAllowRule translates one network.allow entry into an egress allow
// rule.
func ParseAllowRule(entry string) (msb.PolicyRule, error) {
	rule := msb.PolicyRule{Action: msb.PolicyActionAllow, Direction: msb.PolicyDirectionEgress}
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
		return rule, fmt.Errorf(
			"network rule %q: %q is a port, not a protocol; did you mean %s:tcp:%s?",
			entry,
			proto,
			target,
			proto,
		)
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
func parseDNSRule(entry string) (msb.PolicyRule, error) {
	rule := msb.PolicyRule{Action: msb.PolicyActionAllow, Direction: msb.PolicyDirectionEgress, Destination: "host"}
	fields := strings.Split(entry, ":")
	if len(fields) > 3 {
		return rule, trailingJunkError(entry)
	}
	switch len(fields) {
	case 2, 3:
		switch fields[1] {
		case "", "any":
			rule.Protocols = []msb.PolicyProtocol{msb.PolicyProtocolUDP, msb.PolicyProtocolTCP}
		case "udp":
			rule.Protocols = []msb.PolicyProtocol{msb.PolicyProtocolUDP}
		case "tcp":
			rule.Protocols = []msb.PolicyProtocol{msb.PolicyProtocolTCP}
		default:
			return rule, fmt.Errorf(
				"network rule %q: the `dns` target supports `tcp`, `udp`, or `any`, not %q",
				entry,
				fields[1],
			)
		}
		if len(fields) == 3 {
			switch fields[2] {
			case "", "any", "53":
			default:
				return rule, fmt.Errorf(
					"network rule %q: the `dns` target is fixed to port 53; omit the port or use `53`/`any`",
					entry,
				)
			}
		}
	case 1:
		rule.Protocols = []msb.PolicyProtocol{msb.PolicyProtocolUDP, msb.PolicyProtocolTCP}
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
func parseRuleProtocols(proto string, present bool) ([]msb.PolicyProtocol, error) {
	if !present || proto == "any" {
		return nil, nil
	}
	switch proto {
	case "tcp":
		return []msb.PolicyProtocol{msb.PolicyProtocolTCP}, nil
	case "udp":
		return []msb.PolicyProtocol{msb.PolicyProtocolUDP}, nil
	case "icmpv4":
		return []msb.PolicyProtocol{msb.PolicyProtocolICMPv4}, nil
	case "icmpv6":
		return []msb.PolicyProtocol{msb.PolicyProtocolICMPv6}, nil
	default:
		return nil, fmt.Errorf(
			"%q is not a recognized protocol; expected `any`, `tcp`, `udp`, `icmpv4`, or `icmpv6`",
			proto,
		)
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
	return fmt.Errorf(
		"network rule %q has trailing fields after the ports; if this is an IPv6 address, wrap it as [<addr>]",
		entry,
	)
}
