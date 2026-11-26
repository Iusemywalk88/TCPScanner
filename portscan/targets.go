package portscan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Resolver resolves a DNS name to IP addresses. It is the minimal surface of
// *net.Resolver needed by this package.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// target is a single scan target: an IP literal or a DNS name. host is the
// string exactly as passed to Scan, and norm is the normalized form used for
// resolution and de-duplication.
type target struct {
	host string
	norm string
	ip   netip.Addr
	isIP bool
}

// parseTargets validates and normalizes every host in hosts without touching
// the network. It returns nil and an error wrapping ErrInvalidTarget if hosts
// is empty or any host is invalid; every invalid host is reported through
// errors.Join. Duplicate targets (by normalized form) are removed, keeping
// the first occurrence and preserving order.
func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: no targets", ErrInvalidTarget)
	}

	targets := make([]target, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	var errs []error
	for _, host := range hosts {
		t, err := parseTarget(host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, ok := seen[t.norm]; ok {
			continue
		}
		seen[t.norm] = struct{}{}
		targets = append(targets, t)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return targets, nil
}

// parseTarget parses and validates a single host. A syntactically valid IP
// literal becomes an IP target without any resolution; otherwise the string
// is validated as a DNS name.
func parseTarget(host string) (target, error) {
	if host == "" {
		return target{}, fmt.Errorf("%w: %q is empty", ErrInvalidTarget, host)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		return target{host: host, norm: addr.String(), ip: addr, isIP: true}, nil
	}
	norm, err := normalizeHostname(host)
	if err != nil {
		return target{}, fmt.Errorf("%w: %q: %v", ErrInvalidTarget, host, err)
	}
	return target{host: host, norm: norm}, nil
}

// normalizeHostname validates host as a DNS name and returns its lowercase
// form without a trailing root dot. Hostnames are restricted to ASCII
// letters, digits, hyphen, underscore, and dots; internationalized names
// must be passed in punycode (xn--) form.
func normalizeHostname(host string) (string, error) {
	s := host
	// Allow a single trailing root dot.
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
		if s == "" {
			return "", fmt.Errorf("root domain")
		}
	}
	if len(s) > 253 {
		return "", fmt.Errorf("name length %d exceeds 253", len(s))
	}

	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("label length %d exceeds 63", len(label))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("label %q starts or ends with a hyphen", label)
		}
		for _, c := range label {
			if !isHostnameChar(c) {
				return "", fmt.Errorf("invalid character %q", c)
			}
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("last label is all digits")
	}
	return strings.ToLower(s), nil
}

// isHostnameChar reports whether c is allowed in a hostname label.
func isHostnameChar(c rune) bool {
	return c == '-' || c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// allDigits reports whether s is non-empty and consists only of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// resolveTarget resolves a single target to its IP addresses. IP literals are
// returned without calling the resolver. For DNS names the resolver is called
// and the result is unmapped and de-duplicated in order. A resolver error is
// wrapped so that both ErrResolve and the original error are reachable with
// errors.Is and errors.As, unless the context was canceled, in which case the
// context error is returned unwrapped.
func resolveTarget(ctx context.Context, r Resolver, t target) ([]netip.Addr, error) {
	if t.isIP {
		return []netip.Addr{t.ip}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ips, err := r.LookupNetIP(ctx, "ip", t.norm)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("resolve %q: %w: %w", t.norm, ErrResolve, err)
	}

	out := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %q returned no addresses", ErrResolve, t.norm)
	}
	return out, nil
}

// ipSet tracks the set of IP addresses already scheduled for scanning. It is
// owned by the generator goroutine and is therefore not safe for concurrent
// use; it must be initialized with make before use.
type ipSet map[netip.Addr]struct{}

// add reports whether ip was not already in the set and adds it. It returns
// false if ip was already present.
func (s ipSet) add(ip netip.Addr) bool {
	if _, ok := s[ip]; ok {
		return false
	}
	s[ip] = struct{}{}
	return true
}
