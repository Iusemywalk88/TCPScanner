package portscan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Dialer establishes a TCP connection. It is the minimal surface of
// *net.Dialer needed by this package. It is exported so tests and callers can
// substitute a fake or a custom dialer via WithDialer.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Option configures a Scanner. It is applied to a config by New.
type Option func(*config)

// config holds the runtime configuration of a Scanner. It is populated by
// defaultConfig and mutated by options before a Scanner is built.
type config struct {
	concurrency    int
	connectTimeout time.Duration
	dialer         Dialer
	resolver       Resolver
	errs           []error
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

// WithConcurrency sets the maximum number of simultaneous dials. It must be
// between 1 and 65535: it determines both the number of worker goroutines and
// the size of the results channel buffer, so an unbounded value would exhaust
// memory.
func WithConcurrency(n int) Option {
	return func(c *config) {
		if n < 1 || n > 65535 {
			c.errs = append(c.errs, fmt.Errorf("%w: concurrency %d must be in [1, 65535]", ErrInvalidOption, n))
			return
		}
		c.concurrency = n
	}
}

// WithConnectTimeout sets the timeout for each individual dial attempt.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) {
		if d <= 0 {
			c.errs = append(c.errs, fmt.Errorf("%w: connect timeout %v must be > 0", ErrInvalidOption, d))
			return
		}
		c.connectTimeout = d
	}
}

// WithDialer sets the Dialer used to establish connections. A nil dialer is
// invalid.
func WithDialer(d Dialer) Option {
	return func(c *config) {
		if d == nil {
			c.errs = append(c.errs, fmt.Errorf("%w: dialer must not be nil", ErrInvalidOption))
			return
		}
		c.dialer = d
	}
}

// WithResolver sets the Resolver used to resolve DNS names. A nil resolver is
// invalid.
func WithResolver(r Resolver) Option {
	return func(c *config) {
		if r == nil {
			c.errs = append(c.errs, fmt.Errorf("%w: resolver must not be nil", ErrInvalidOption))
			return
		}
		c.resolver = r
	}
}
