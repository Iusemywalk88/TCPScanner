package portscan

import (
	"net/netip"
	"time"
)

// State describes the outcome of checking a single TCP port on a single IP
// address. The zero value is invalid and must not be used as a result.
type State uint8

// Valid port states reported by Scan.
const (
	// StateOpen means the TCP connection was established.
	StateOpen State = iota + 1
	// StateClosed means the connection was explicitly refused.
	StateClosed
	// StateTimeout means the connection did not complete within the
	// configured timeout.
	StateTimeout
	// StateUnreachable means the host or network was unreachable.
	StateUnreachable
	// StateCanceled means the check was canceled through the context.
	StateCanceled
	// StateError means any other error occurred.
	StateError
)

// String returns the lowercase name of the state. The zero value and any
// unknown value return "invalid".
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "invalid"
	}
}

// Result is the outcome of checking a single TCP port on a single IP address.
type Result struct {
	// Host is the target as passed to Scan.
	Host string
	// IP is the concrete address that was dialed.
	IP netip.Addr
	// Port is the TCP port that was checked.
	Port uint16
	// State classifies the outcome.
	State State
	// Duration is the time spent on the check.
	Duration time.Duration
	// Err is the underlying error, if any. It is nil when State is StateOpen.
	Err error
}
