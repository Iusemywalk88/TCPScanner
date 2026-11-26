package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn whose Close is a no-op.
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (fakeConn) Write([]byte) (int, error)        { return 0, nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return nil }
func (fakeConn) RemoteAddr() net.Addr             { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

// closeConn is a fakeConn whose Close calls are counted via a shared counter.
type closeConn struct {
	fakeConn
	closes *atomic.Int64
}

func (c *closeConn) Close() error {
	c.closes.Add(1)
	return nil
}

// countingDialer succeeds on every dial and counts dials and closes.
type countingDialer struct {
	dials  atomic.Int64
	closes atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	return &closeConn{closes: &d.closes}, nil
}

// stateDialer returns a per-port error (nil means success).
type stateDialer struct {
	byPort map[uint16]error
}

func (d *stateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	port, err := portFromAddress(address)
	if err != nil {
		return nil, err
	}
	e, ok := d.byPort[port]
	if !ok {
		return nil, errors.New("unexpected port")
	}
	if e == nil {
		return fakeConn{}, nil
	}
	return nil, e
}

// gateDialer blocks on a gate until it is opened, tracking in-flight dials.
type gateDialer struct {
	gate    chan struct{}
	started chan struct{}
	current atomic.Int64
	max     atomic.Int64
}

func (d *gateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cur := d.current.Add(1)
	for {
		m := d.max.Load()
		if cur <= m || d.max.CompareAndSwap(m, cur) {
			break
		}
	}
	d.started <- struct{}{}
	<-d.gate
	d.current.Add(-1)
	return fakeConn{}, nil
}

// cancelDialer blocks until the dial context is done, then fails with it.
type cancelDialer struct {
	dials atomic.Int64
}

func (d *cancelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func portFromAddress(address string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}

func makePorts(n int) []uint16 {
	ports := make([]uint16, n)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	return ports
}

// lit returns an IP-literal target for an IP string.
func lit(ip string) target {
	return target{host: ip, norm: ip, ip: addr(ip), isIP: true}
}

// waitFor polls cond until it is true or timeout expires. It uses atomic
// loads and runtime.Gosched (no time.Sleep) and exists only for test sync.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// waitClosed drains ch in a goroutine and fails if it does not close within
// timeout.
func waitClosed(t *testing.T, ch <-chan Result, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range ch {
		}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("channel did not close within %v", timeout)
	}
}

func TestRunStates(t *testing.T) {
	d := &stateDialer{byPort: map[uint16]error{
		1: nil,
		2: syscall.ECONNREFUSED,
		3: syscall.ENETUNREACH,
		4: context.DeadlineExceeded,
		5: errors.New("boom"),
	}}
	cfg := config{concurrency: 2, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := []uint16{1, 2, 3, 4, 5}

	out := run(context.Background(), cfg, targets, ports)

	got := make(map[uint16]Result, 5)
	for r := range out {
		got[r.Port] = r
	}
	if len(got) != 5 {
		t.Fatalf("results = %d, want 5", len(got))
	}

	want := map[uint16]State{
		1: StateOpen,
		2: StateClosed,
		3: StateUnreachable,
		4: StateTimeout,
		5: StateError,
	}
	for port, state := range want {
		r, ok := got[port]
		if !ok {
			t.Fatalf("missing result for port %d", port)
		}
		if r.State != state {
			t.Errorf("port %d state = %v, want %v", port, r.State, state)
		}
		if r.Host == "" {
			t.Errorf("port %d host is empty", port)
		}
		if r.IP != addr("192.0.2.1") {
			t.Errorf("port %d ip = %v, want 192.0.2.1", port, r.IP)
		}
		if r.Duration <= 0 {
			t.Errorf("port %d duration = %v, want > 0", port, r.Duration)
		}
		if state == StateOpen && r.Err != nil {
			t.Errorf("port %d open but Err = %v", port, r.Err)
		}
		if state != StateOpen && r.Err == nil {
			t.Errorf("port %d state %v but Err = nil", port, state)
		}
	}
}

func TestRunClosesConnections(t *testing.T) {
	d := &countingDialer{}
	cfg := config{concurrency: 4, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(20)

	out := run(context.Background(), cfg, targets, ports)

	var results int
	for range out {
		results++
	}
	if results != len(ports) {
		t.Fatalf("results = %d, want %d", results, len(ports))
	}
	if d.dials.Load() != int64(len(ports)) {
		t.Fatalf("dials = %d, want %d", d.dials.Load(), len(ports))
	}
	if d.closes.Load() != d.dials.Load() {
		t.Fatalf("closes = %d, dials = %d, want equal", d.closes.Load(), d.dials.Load())
	}
}

func TestRunConcurrencyLimit(t *testing.T) {
	const n = 5
	const total = 100

	d := &gateDialer{
		gate:    make(chan struct{}),
		started: make(chan struct{}, total),
	}
	cfg := config{concurrency: n, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(total)

	out := run(context.Background(), cfg, targets, ports)

	// Wait until exactly n dials are in flight (blocked on the gate).
	for i := 0; i < n; i++ {
		<-d.started
	}
	if got := d.current.Load(); got != n {
		t.Fatalf("in-flight dials = %d, want %d", got, n)
	}

	// Open the gate, then drain everything.
	close(d.gate)
	var results int
	for range out {
		results++
	}
	if results != total {
		t.Fatalf("results = %d, want %d", results, total)
	}
	if got := d.max.Load(); got != n {
		t.Fatalf("max in-flight dials = %d, want %d", got, n)
	}
}

func TestRunCancellation(t *testing.T) {
	const n = 5
	const total = 1000

	d := &cancelDialer{}
	cfg := config{concurrency: n, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(total)

	ctx, cancel := context.WithCancel(context.Background())
	out := run(ctx, cfg, targets, ports)

	// Wait until n dials have started (all blocked on ctx.Done).
	waitFor(t, "n dials started", 5*time.Second, func() bool {
		return d.dials.Load() >= n
	})

	cancel()

	// Drain; the channel must close within the timeout.
	var results int
	deadline := time.After(5 * time.Second)
drain:
	for {
		select {
		case r, ok := <-out:
			if !ok {
				break drain
			}
			if r.State != StateCanceled {
				t.Errorf("state = %v, want canceled", r.State)
			}
			results++
		case <-deadline:
			t.Fatal("out did not close after cancellation")
		}
	}

	started := d.dials.Load()
	if started >= total {
		t.Fatalf("started dials = %d, want < %d", started, total)
	}
	if int64(results) > started {
		t.Fatalf("results = %d, want <= started dials %d", results, started)
	}
	if results == 0 {
		t.Fatal("no canceled results delivered")
	}
}

func TestRunBackpressure(t *testing.T) {
	const n = 5
	const total = 200

	d := &countingDialer{}
	cfg := config{concurrency: n, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(total)

	out := run(context.Background(), cfg, targets, ports)

	// The reader does not consume out yet. Workers fill the out buffer (n)
	// and then block in send each holding one result, so the dial count
	// plateaus at 2n (n buffered + n blocked). Allow +n slack for boundary
	// races.
	waitFor(t, "dial plateau", 5*time.Second, func() bool {
		return d.dials.Load() >= 2*n
	})

	// Sanctioned single time.Sleep: assert nothing more happens (backpressure)
	// now that the reader is absent.
	time.Sleep(50 * time.Millisecond)
	if got := d.dials.Load(); got > 2*n+n {
		t.Fatalf("dials = %d, want <= %d (no backpressure)", got, 2*n+n)
	}

	// Now read everything: every result must arrive with no loss.
	var results int
	for range out {
		results++
	}
	if results != total {
		t.Fatalf("results = %d, want %d", results, total)
	}
}

func TestRunCancelWithoutReader(t *testing.T) {
	d := &countingDialer{}
	cfg := config{concurrency: 4, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(1000)

	ctx, cancel := context.WithCancel(context.Background())
	out := run(ctx, cfg, targets, ports)
	cancel() // reader leaves without reading

	// out must still close: cancel unblocks send, workers exit, closer closes.
	waitClosed(t, out, 5*time.Second)
}

func TestRunResolveError(t *testing.T) {
	res := &fakeResolver{results: map[string][]netip.Addr{
		"good.example": {addr("192.0.2.1")},
		// "bad.example" intentionally absent → empty response → ErrResolve.
	}}
	d := &countingDialer{}
	cfg := config{concurrency: 2, connectTimeout: time.Second, dialer: d, resolver: res}
	targets := []target{
		{host: "bad.example", norm: "bad.example"},
		{host: "good.example", norm: "good.example"},
	}
	ports := []uint16{80, 443}

	out := run(context.Background(), cfg, targets, ports)

	var bad, good int
	for r := range out {
		switch r.Host {
		case "bad.example":
			bad++
			if r.State != StateError {
				t.Errorf("bad state = %v, want error", r.State)
			}
			if r.Port != 0 {
				t.Errorf("bad port = %d, want 0", r.Port)
			}
			if !errors.Is(r.Err, ErrResolve) {
				t.Errorf("bad err = %v, want ErrResolve", r.Err)
			}
		case "good.example":
			good++
			if r.State != StateOpen {
				t.Errorf("good state = %v, want open", r.State)
			}
		default:
			t.Errorf("unexpected host %q", r.Host)
		}
	}

	if bad != 1 {
		t.Fatalf("bad results = %d, want 1", bad)
	}
	if good != 2 {
		t.Fatalf("good results = %d, want 2", good)
	}
}

func TestRunDedupAcrossHosts(t *testing.T) {
	res := &fakeResolver{results: map[string][]netip.Addr{
		"localhost": {addr("127.0.0.1")},
	}}
	d := &countingDialer{}
	cfg := config{concurrency: 2, connectTimeout: time.Second, dialer: d, resolver: res}
	targets := []target{
		{host: "localhost", norm: "localhost"},
		{host: "127.0.0.1", norm: "127.0.0.1", ip: addr("127.0.0.1"), isIP: true},
	}
	ports := []uint16{80, 443}

	out := run(context.Background(), cfg, targets, ports)

	var results int
	for r := range out {
		results++
		if r.IP != addr("127.0.0.1") {
			t.Errorf("ip = %v, want 127.0.0.1", r.IP)
		}
	}
	if results != 2 {
		t.Fatalf("results = %d, want 2 (each port once)", results)
	}
}

func TestRunMultipleIPs(t *testing.T) {
	res := &fakeResolver{results: map[string][]netip.Addr{
		"multi.example": {addr("192.0.2.1"), addr("2001:db8::1")},
	}}
	d := &countingDialer{}
	cfg := config{concurrency: 2, connectTimeout: time.Second, dialer: d, resolver: res}
	targets := []target{{host: "multi.example", norm: "multi.example"}}
	ports := []uint16{80, 443}

	out := run(context.Background(), cfg, targets, ports)

	seen := make(map[netip.Addr]int)
	for r := range out {
		seen[r.IP]++
		if r.Host != "multi.example" {
			t.Errorf("host = %q, want multi.example", r.Host)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("distinct IPs = %d, want 2", len(seen))
	}
	for ip, n := range seen {
		if n != 2 {
			t.Errorf("ip %v has %d results, want 2", ip, n)
		}
	}
}

func TestRunCanceledBefore(t *testing.T) {
	d := &countingDialer{}
	cfg := config{concurrency: 2, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := []uint16{80, 443}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := run(ctx, cfg, targets, ports)
	waitClosed(t, out, 5*time.Second)

	if d.dials.Load() != 0 {
		t.Fatalf("dials = %d, want 0", d.dials.Load())
	}
}

func TestRunConcurrentUse(t *testing.T) {
	d := &countingDialer{}
	cfg := config{concurrency: 4, connectTimeout: time.Second, dialer: d, resolver: &fakeResolver{}}
	targets := []target{lit("192.0.2.1")}
	ports := makePorts(20)

	const runs = 10
	errCh := make(chan error, runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := run(context.Background(), cfg, targets, ports)
			var results int
			var err error
			for r := range out {
				if r.State != StateOpen && err == nil {
					err = fmt.Errorf("state = %v, want open", r.State)
				}
				results++
			}
			if err == nil && results != len(ports) {
				err = fmt.Errorf("results = %d, want %d", results, len(ports))
			}
			errCh <- err
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
