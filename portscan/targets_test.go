package portscan

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeResolver is a test double for Resolver with a call counter.
type fakeResolver struct {
	calls   int
	results map[string][]netip.Addr
	err     error
	network string
	host    string
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.calls++
	f.network = network
	f.host = host
	if f.err != nil {
		return nil, f.err
	}
	return f.results[host], nil
}

func addr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func TestParseTargetsIPLiterals(t *testing.T) {
	tests := []struct {
		name string
		host string
		norm string
	}{
		{"ipv4", "192.0.2.1", "192.0.2.1"},
		{"ipv6", "2001:db8::1", "2001:db8::1"},
		{"ipv6 zone", "fe80::1%eth0", "fe80::1%eth0"},
		{"ipv4-mapped", "::ffff:192.0.2.1", "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := parseTargets([]string{tt.host})
			if err != nil {
				t.Fatalf("parseTargets(%q) error: %v", tt.host, err)
			}
			if len(targets) != 1 {
				t.Fatalf("len = %d, want 1", len(targets))
			}
			got := targets[0]
			if got.host != tt.host {
				t.Errorf("host = %q, want %q", got.host, tt.host)
			}
			if got.norm != tt.norm {
				t.Errorf("norm = %q, want %q", got.norm, tt.norm)
			}
			if !got.isIP {
				t.Errorf("isIP = false, want true")
			}
			if !got.ip.IsValid() || got.ip.String() != tt.norm {
				t.Errorf("ip = %v, want %q", got.ip, tt.norm)
			}
		})
	}
}

func TestParseTargetsValidNames(t *testing.T) {
	tests := []struct {
		name string
		host string
		norm string
	}{
		{"localhost", "localhost", "localhost"},
		{"uppercase", "Example.COM", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"underscore", "a_b.example.com", "a_b.example.com"},
		{"63 char label", strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := parseTargets([]string{tt.host})
			if err != nil {
				t.Fatalf("parseTargets(%q) error: %v", tt.host, err)
			}
			if len(targets) != 1 {
				t.Fatalf("len = %d, want 1", len(targets))
			}
			if targets[0].host != tt.host {
				t.Errorf("host = %q, want %q", targets[0].host, tt.host)
			}
			if targets[0].norm != tt.norm {
				t.Errorf("norm = %q, want %q", targets[0].norm, tt.norm)
			}
			if targets[0].isIP {
				t.Errorf("isIP = true, want false")
			}
		})
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	label64 := strings.Repeat("a", 64) + ".com"
	name254 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)

	tests := []struct {
		name string
		host string
	}{
		{"empty", ""},
		{"space", " "},
		{"leading space", " a.com"},
		{"inner space", "a b"},
		{"slash", "a/b"},
		{"colon port", "a:80"},
		{"brackets", "[::1]"},
		{"empty label", "foo..bar"},
		{"leading dot", ".a.com"},
		{"root only", "."},
		{"leading hyphen", "-a.com"},
		{"trailing hyphen", "a-.com"},
		{"64 char label", label64},
		{"254 char name", name254},
		{"numeric ip too high", "192.168.1.999"},
		{"numeric three labels", "1.2.3"},
		{"numeric single", "123"},
		{"idn unicode", "пример.рф"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := parseTargets([]string{tt.host})
			if err == nil {
				t.Fatalf("parseTargets(%q) = %v, want error", tt.host, targets)
			}
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("parseTargets(%q) error = %v, want to wrap ErrInvalidTarget", tt.host, err)
			}
		})
	}
}

func TestParseTargetsMultipleInvalid(t *testing.T) {
	hosts := []string{"a..b", "c d", "e/f"}
	_, err := parseTargets(hosts)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("error = %v, want to wrap ErrInvalidTarget", err)
	}
	for _, h := range hosts {
		if !strings.Contains(err.Error(), h) {
			t.Errorf("error %q does not mention host %q", err, h)
		}
	}
}

func TestParseTargetsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := parseTargets(tt.hosts)
			if err == nil {
				t.Fatalf("parseTargets(%v) = %v, want error", tt.hosts, targets)
			}
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("error = %v, want to wrap ErrInvalidTarget", err)
			}
			if !strings.Contains(err.Error(), "no targets") {
				t.Fatalf("error = %v, want to mention \"no targets\"", err)
			}
		})
	}
}

func TestParseTargetsOrder(t *testing.T) {
	targets, err := parseTargets([]string{"b.com", "a.com", "B.com", "c.com"})
	if err != nil {
		t.Fatalf("parseTargets error: %v", err)
	}
	want := []string{"b.com", "a.com", "c.com"}
	if len(targets) != len(want) {
		t.Fatalf("len = %d, want %d", len(targets), len(want))
	}
	for i := range targets {
		if targets[i].host != want[i] {
			t.Errorf("targets[%d].host = %q, want %q", i, targets[i].host, want[i])
		}
	}
}

func TestParseTargetsDedup(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		want  []string
	}{
		{"case insensitive", []string{"Example.com", "example.com"}, []string{"Example.com"}},
		{"trailing dot", []string{"example.com", "example.com."}, []string{"example.com"}},
		{"mapped ip", []string{"::ffff:192.0.2.1", "192.0.2.1"}, []string{"::ffff:192.0.2.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := parseTargets(tt.hosts)
			if err != nil {
				t.Fatalf("parseTargets error: %v", err)
			}
			if len(targets) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(targets), len(tt.want))
			}
			for i := range targets {
				if targets[i].host != tt.want[i] {
					t.Errorf("targets[%d].host = %q, want %q", i, targets[i].host, tt.want[i])
				}
			}
		})
	}
}

func TestResolveTargetLiteralNoResolver(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"ipv4", "192.0.2.1", "192.0.2.1"},
		{"ipv6", "2001:db8::1", "2001:db8::1"},
		{"ipv6 zone", "fe80::1%eth0", "fe80::1%eth0"},
		{"ipv4-mapped", "::ffff:192.0.2.1", "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeResolver{}
			targets, err := parseTargets([]string{tt.host})
			if err != nil {
				t.Fatalf("parseTargets error: %v", err)
			}
			ips, err := resolveTarget(context.Background(), fake, targets[0])
			if err != nil {
				t.Fatalf("resolveTarget error: %v", err)
			}
			if len(ips) != 1 || ips[0].String() != tt.want {
				t.Fatalf("ips = %v, want [%s]", ips, tt.want)
			}
			if fake.calls != 0 {
				t.Errorf("resolver calls = %d, want 0", fake.calls)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	tests := []struct {
		name    string
		results map[string][]netip.Addr
		norm    string
		want    []netip.Addr
	}{
		{
			"multiple ips",
			map[string][]netip.Addr{"example.com": {addr("192.0.2.1"), addr("2001:db8::1")}},
			"example.com",
			[]netip.Addr{addr("192.0.2.1"), addr("2001:db8::1")},
		},
		{
			"dedup and unmap",
			map[string][]netip.Addr{"example.com": {addr("::ffff:192.0.2.1"), addr("192.0.2.1"), addr("2001:db8::1")}},
			"example.com",
			[]netip.Addr{addr("192.0.2.1"), addr("2001:db8::1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeResolver{results: tt.results}
			ips, err := resolveTarget(context.Background(), fake, target{norm: tt.norm})
			if err != nil {
				t.Fatalf("resolveTarget error: %v", err)
			}
			if !slices.Equal(ips, tt.want) {
				t.Fatalf("ips = %v, want %v", ips, tt.want)
			}
			if fake.calls != 1 {
				t.Errorf("resolver calls = %d, want 1", fake.calls)
			}
			if fake.network != "ip" {
				t.Errorf("network = %q, want %q", fake.network, "ip")
			}
			if fake.host != tt.norm {
				t.Errorf("host = %q, want %q", fake.host, tt.norm)
			}
		})
	}
}

func TestResolveTargetErrors(t *testing.T) {
	t.Run("resolver error", func(t *testing.T) {
		orig := errors.New("boom")
		fake := &fakeResolver{err: orig}
		_, err := resolveTarget(context.Background(), fake, target{norm: "example.com"})
		if err == nil {
			t.Fatal("want error")
		}
		if !errors.Is(err, ErrResolve) {
			t.Errorf("error = %v, want to wrap ErrResolve", err)
		}
		if !errors.Is(err, orig) {
			t.Errorf("error = %v, want to wrap original error", err)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		fake := &fakeResolver{results: map[string][]netip.Addr{"example.com": {}}}
		_, err := resolveTarget(context.Background(), fake, target{norm: "example.com"})
		if err == nil {
			t.Fatal("want error")
		}
		if !errors.Is(err, ErrResolve) {
			t.Errorf("error = %v, want to wrap ErrResolve", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fake := &fakeResolver{}
		_, err := resolveTarget(ctx, fake, target{norm: "example.com"})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
		if errors.Is(err, ErrResolve) {
			t.Errorf("error = %v, should not wrap ErrResolve", err)
		}
		if fake.calls != 0 {
			t.Errorf("resolver calls = %d, want 0", fake.calls)
		}
	})
}

func TestIPSet(t *testing.T) {
	fake := &fakeResolver{results: map[string][]netip.Addr{
		"localhost": {addr("127.0.0.1"), addr("::1")},
		"mapped":    {addr("::ffff:127.0.0.1")},
	}}

	set := make(ipSet)

	// localhost resolves to 127.0.0.1 and ::1.
	ips, err := resolveTarget(context.Background(), fake, target{norm: "localhost"})
	if err != nil {
		t.Fatalf("resolveTarget(localhost): %v", err)
	}
	for _, ip := range ips {
		if !set.add(ip) {
			t.Fatalf("add(%v) = false on first insert", ip)
		}
	}

	// A literal 127.0.0.1 resolves to the already-added 127.0.0.1.
	lit := target{norm: "127.0.0.1", ip: addr("127.0.0.1"), isIP: true}
	ips, err = resolveTarget(context.Background(), fake, lit)
	if err != nil {
		t.Fatalf("resolveTarget(127.0.0.1): %v", err)
	}
	if set.add(ips[0]) {
		t.Error("add(127.0.0.1) = true, want false (duplicate)")
	}

	// A mapped address unmaps to 127.0.0.1 and is the same IP.
	ips, err = resolveTarget(context.Background(), fake, target{norm: "mapped"})
	if err != nil {
		t.Fatalf("resolveTarget(mapped): %v", err)
	}
	if len(ips) != 1 || ips[0] != addr("127.0.0.1") {
		t.Fatalf("mapped resolved to %v, want [127.0.0.1]", ips)
	}
	if set.add(ips[0]) {
		t.Error("add(unmapped mapped IP) = true, want false (duplicate)")
	}
}
