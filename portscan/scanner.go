package portscan

import (
	"context"
	"errors"
	"fmt"
)

// Scanner performs TCP connect scans. It is immutable after New and safe for
// concurrent use.
type Scanner struct {
	cfg config
}

// New builds a Scanner from the given options. It returns an error wrapping
// ErrInvalidOption if any option is invalid; all option errors are reported
// together via errors.Join. A nil option is ignored.
func New(opts ...Option) (*Scanner, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	if len(cfg.errs) > 0 {
		return nil, errors.Join(cfg.errs...)
	}
	return &Scanner{cfg: cfg}, nil
}

// Scan checks every host×port pair and streams the results to the returned
// channel.
//
// Scan returns an error and a nil channel in these cases:
//
//   - invalid ports or hosts: an error joined from ErrInvalidPort and/or
//     ErrInvalidTarget via errors.Join;
//   - a context that is already canceled or expired: ctx.Err();
//   - a zero-value or nil Scanner: an error wrapping ErrInvalidOption.
//
// An unresolvable host yields a single Result with State=StateError, Port=0,
// a zero IP, and Err wrapping ErrResolve. Targets that resolve to the same IP
// are scanned once. A DNS name with multiple addresses is scanned on every
// address.
//
// DNS names are resolved sequentially in a single goroutine, bounded only by
// ctx and the resolver's own timeouts (WithConnectTimeout does not apply to
// resolution). A hung resolution of one name delays the scanning of all
// subsequent targets until it completes or ctx is canceled.
//
// The returned channel must be drained to completion or ctx must be canceled,
// otherwise the scan goroutines leak. The order of results is unspecified,
// and the concurrency limit applies to this single call. After the channel is
// closed, the reason for an early stop (if any) is available via ctx.Err().
//
// ctx must be non-nil.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSpec) (<-chan Result, error) {
	if s == nil || s.cfg.dialer == nil {
		return nil, fmt.Errorf("%w: Scanner must be created with New", ErrInvalidOption)
	}

	normPorts, errPorts := normalizePorts(ports)
	targets, errTargets := parseTargets(hosts)

	var errs []error
	if errPorts != nil {
		errs = append(errs, errPorts)
	}
	if errTargets != nil {
		errs = append(errs, errTargets)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return run(ctx, s.cfg, targets, normPorts), nil
}
