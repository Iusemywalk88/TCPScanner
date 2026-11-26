package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if s.cfg.concurrency != 100 {
		t.Errorf("concurrency = %d, want 100", s.cfg.concurrency)
	}
	if s.cfg.connectTimeout != time.Second {
		t.Errorf("connectTimeout = %v, want 1s", s.cfg.connectTimeout)
	}
	if s.cfg.dialer == nil {
		t.Error("dialer is nil")
	}
	if s.cfg.resolver == nil {
		t.Error("resolver is nil")
	}
}

func TestNewOptions(t *testing.T) {
	d := &countingDialer{}
	r := &fakeResolver{}
	s, err := New(
		WithConcurrency(7),
		WithConnectTimeout(3*time.Second),
		WithDialer(d),
		WithResolver(r),
	)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if s.cfg.concurrency != 7 {
		t.Errorf("concurrency = %d, want 7", s.cfg.concurrency)
	}
	if s.cfg.connectTimeout != 3*time.Second {
		t.Errorf("connectTimeout = %v, want 3s", s.cfg.connectTimeout)
	}
	if s.cfg.dialer != d {
		t.Errorf("dialer = %v, want %v", s.cfg.dialer, d)
	}
	if s.cfg.resolver != r {
		t.Errorf("resolver = %v, want %v", s.cfg.resolver, r)
	}
}

func TestNewInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  Option
	}{
		{"concurrency zero", WithConcurrency(0)},
		{"concurrency negative", WithConcurrency(-1)},
		{"concurrency too large", WithConcurrency(65536)},
		{"timeout zero", WithConnectTimeout(0)},
		{"timeout negative", WithConnectTimeout(-time.Second)},
		{"nil dialer", WithDialer(nil)},
		{"nil resolver", WithResolver(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(tt.opt)
			if err == nil {
				t.Fatalf("New(%v) = %v, want error", tt.opt, s)
			}
			if !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("error = %v, want ErrInvalidOption", err)
			}
		})
	}
}

func TestNewMultipleInvalidOptions(t *testing.T) {
	_, err := New(
		WithConcurrency(0),
		WithConnectTimeout(-time.Second),
		WithDialer(nil),
		WithResolver(nil),
	)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("error = %v, want ErrInvalidOption", err)
	}
	for _, sub := range []string{"concurrency", "timeout", "dialer", "resolver"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q does not mention %q", err, sub)
		}
	}
}

func TestNewNilOptionIgnored(t *testing.T) {
	s, err := New(nil, WithConcurrency(3), nil)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if s.cfg.concurrency != 3 {
		t.Errorf("concurrency = %d, want 3", s.cfg.concurrency)
	}
}

func TestScanValidation(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	ctx := context.Background()

	t.Run("bad host", func(t *testing.T) {
		ch, err := s.Scan(ctx, []string{"a..b"}, Ports(80))
		if err == nil {
			t.Fatal("want error")
		}
		if ch != nil {
			t.Error("channel = non-nil, want nil")
		}
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("error = %v, want ErrInvalidTarget", err)
		}
	})

	t.Run("bad port", func(t *testing.T) {
		ch, err := s.Scan(ctx, []string{"localhost"}, Ports(0))
		if err == nil {
			t.Fatal("want error")
		}
		if ch != nil {
			t.Error("channel = non-nil, want nil")
		}
		if !errors.Is(err, ErrInvalidPort) {
			t.Errorf("error = %v, want ErrInvalidPort", err)
		}
	})

	t.Run("empty hosts", func(t *testing.T) {
		_, err := s.Scan(ctx, nil, Ports(80))
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("error = %v, want ErrInvalidTarget", err)
		}
	})

	t.Run("empty ports", func(t *testing.T) {
		_, err := s.Scan(ctx, []string{"localhost"}, PortSpec{})
		if !errors.Is(err, ErrInvalidPort) {
			t.Errorf("error = %v, want ErrInvalidPort", err)
		}
	})

	t.Run("both invalid", func(t *testing.T) {
		ch, err := s.Scan(ctx, []string{"a..b"}, Ports(0))
		if err == nil {
			t.Fatal("want error")
		}
		if ch != nil {
			t.Error("channel = non-nil, want nil")
		}
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("error = %v, want ErrInvalidTarget", err)
		}
		if !errors.Is(err, ErrInvalidPort) {
			t.Errorf("error = %v, want ErrInvalidPort", err)
		}
	})
}

func TestScanOrder(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Invalid input + canceled ctx → validation error, not ctx.Err().
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := s.Scan(ctx, []string{"a..b"}, Ports(80))
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("error = %v, want ErrInvalidTarget (not context.Canceled)", err)
	}
	if ch != nil {
		t.Error("channel = non-nil, want nil")
	}

	// Valid input + canceled ctx → context.Canceled, nil channel, no dial.
	d := &countingDialer{}
	s2, err := New(WithDialer(d))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	ch2, err := s2.Scan(ctx, []string{"192.0.2.1"}, Ports(80))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if ch2 != nil {
		t.Error("channel = non-nil, want nil")
	}
	if d.dials.Load() != 0 {
		t.Errorf("dials = %d, want 0", d.dials.Load())
	}
}

func TestScanZeroScanner(t *testing.T) {
	ctx := context.Background()

	var nilScanner *Scanner
	if _, err := nilScanner.Scan(ctx, []string{"localhost"}, Ports(80)); err == nil {
		t.Fatal("nil Scanner: want error")
	} else if !errors.Is(err, ErrInvalidOption) {
		t.Errorf("nil Scanner error = %v, want ErrInvalidOption", err)
	}

	zero := &Scanner{}
	if _, err := zero.Scan(ctx, []string{"localhost"}, Ports(80)); err == nil {
		t.Fatal("zero Scanner: want error")
	} else if !errors.Is(err, ErrInvalidOption) {
		t.Errorf("zero Scanner error = %v, want ErrInvalidOption", err)
	}
}

func TestScanEndToEnd(t *testing.T) {
	res := &fakeResolver{results: map[string][]netip.Addr{
		"multi.example": {addr("192.0.2.1"), addr("2001:db8::1")},
		// "bad.example" absent → empty response → ErrResolve.
	}}
	d := &countingDialer{}
	s, err := New(WithConcurrency(2), WithDialer(d), WithResolver(res))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	hosts := []string{"multi.example", "bad.example", "multi.example"}
	ch, err := s.Scan(context.Background(), hosts, Ports(80, 443))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	type key struct {
		host string
		ip   string
		port uint16
	}
	got := make(map[key]Result)
	for r := range ch {
		got[key{r.Host, r.IP.String(), r.Port}] = r
	}

	// 4 open (multi.example × 2 IPs × 2 ports) + 1 error (bad.example).
	if len(got) != 5 {
		t.Fatalf("results = %d, want 5: %v", len(got), got)
	}

	var bad int
	for k, r := range got {
		if k.host == "bad.example" {
			bad++
			if r.State != StateError || r.Port != 0 || !errors.Is(r.Err, ErrResolve) {
				t.Errorf("bad result = %+v, want error/port0/ErrResolve", r)
			}
			continue
		}
		if r.State != StateOpen {
			t.Errorf("%v state = %v, want open", k, r.State)
		}
	}
	if bad != 1 {
		t.Fatalf("bad results = %d, want 1", bad)
	}
}

func TestScanRealNetwork(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("real network scan only runs on linux and darwin")
	}
	s, err := New(WithConcurrency(2))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	openPort := uint16(l.Addr().(*net.TCPAddr).Port)

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := uint16(l2.Addr().(*net.TCPAddr).Port)
	if err := l2.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, Ports(int(openPort), int(closedPort)))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	got := make(map[uint16]State)
	for r := range ch {
		got[r.Port] = r.State
	}

	if got[openPort] != StateOpen {
		t.Errorf("open port %d state = %v, want open", openPort, got[openPort])
	}
	if got[closedPort] != StateClosed {
		t.Errorf("closed port %d state = %v, want closed", closedPort, got[closedPort])
	}
}

func TestScanReuse(t *testing.T) {
	d := &countingDialer{}
	s, err := New(WithConcurrency(4), WithDialer(d))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Sequential reuse: two Scans on the same Scanner.
	for i := 0; i < 2; i++ {
		ch, err := s.Scan(context.Background(), []string{"192.0.2.1"}, Ports(80, 443))
		if err != nil {
			t.Fatalf("Scan %d error: %v", i, err)
		}
		var results int
		for r := range ch {
			if r.State != StateOpen {
				t.Errorf("scan %d state = %v, want open", i, r.State)
			}
			results++
		}
		if results != 2 {
			t.Fatalf("scan %d results = %d, want 2", i, results)
		}
	}

	// Parallel reuse: ten Scans on the same Scanner under -race.
	const runs = 10
	errCh := make(chan error, runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := s.Scan(context.Background(), []string{"192.0.2.1"}, Ports(80, 443))
			if err != nil {
				errCh <- err
				return
			}
			var results int
			var scanErr error
			for r := range ch {
				if r.State != StateOpen && scanErr == nil {
					scanErr = fmt.Errorf("state = %v, want open", r.State)
				}
				results++
			}
			if scanErr == nil && results != 2 {
				scanErr = fmt.Errorf("results = %d, want 2", results)
			}
			errCh <- scanErr
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Error(err)
		}
	}
}

// recordingDialer records the network and address of every dial.
type recordingDialer struct {
	networks  []string
	addresses []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.networks = append(d.networks, network)
	d.addresses = append(d.addresses, address)
	return fakeConn{}, nil
}

func TestDialerAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"ipv4", "192.0.2.1", "192.0.2.1:80"},
		{"ipv6", "2001:db8::1", "[2001:db8::1]:80"},
		{"ipv6 zone", "fe80::1%eth0", "[fe80::1%eth0]:80"},
		{"ipv4-mapped", "::ffff:192.0.2.1", "192.0.2.1:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &recordingDialer{}
			s, err := New(WithConcurrency(1), WithDialer(d))
			if err != nil {
				t.Fatalf("New error: %v", err)
			}
			ch, err := s.Scan(context.Background(), []string{tt.host}, Ports(80))
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			for range ch {
			}

			if len(d.addresses) != 1 {
				t.Fatalf("addresses = %v, want 1 dial", d.addresses)
			}
			if d.addresses[0] != tt.want {
				t.Errorf("address = %q, want %q", d.addresses[0], tt.want)
			}
			if d.networks[0] != "tcp" {
				t.Errorf("network = %q, want tcp", d.networks[0])
			}
		})
	}
}

func TestScanFullRange(t *testing.T) {
	d := &countingDialer{}
	s, err := New(WithConcurrency(100), WithDialer(d))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	ch, err := s.Scan(context.Background(), []string{"192.0.2.1"}, Range(1, 65535))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	done := make(chan int, 1)
	go func() {
		seen := make(map[uint16]struct{}, 65535)
		for r := range ch {
			if _, dup := seen[r.Port]; dup {
				t.Errorf("duplicate port %d", r.Port)
			}
			seen[r.Port] = struct{}{}
		}
		done <- len(seen)
	}()

	select {
	case distinct := <-done:
		if distinct != 65535 {
			t.Fatalf("distinct ports = %d, want 65535", distinct)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("full range scan did not complete within 30s")
	}
}

func TestScanIPv6(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("real network scan only runs on linux and darwin")
	}

	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v", err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)

	s, err := New(WithConcurrency(2))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	ch, err := s.Scan(context.Background(), []string{"::1"}, Ports(int(port)))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	var results int
	for r := range ch {
		results++
		if r.State != StateOpen {
			t.Errorf("state = %v, want open", r.State)
		}
	}
	if results != 1 {
		t.Fatalf("results = %d, want 1", results)
	}
}
