package portscan

import (
	"context"
	"net"
	"time"
)

// Dialer establishes a TCP connection. It is the minimal surface of
// *net.Dialer needed by this package.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// config holds the runtime configuration of a Scanner. It is populated by
// defaultConfig and mutated by options before a Scanner is built.
type config struct {
	concurrency    int
	connectTimeout time.Duration
	dialer         Dialer
	resolver       Resolver
}

// defaultConfig returns the default configuration used by New.
func defaultConfig() config {
	return config{
		concurrency:    100,
		connectTimeout: time.Second,
		dialer:         &net.Dialer{},
		resolver:       net.DefaultResolver,
	}
}
