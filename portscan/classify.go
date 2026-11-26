package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// classifyState maps a dial error to a State. The order of the checks is
// significant:
//
//   - A nil error means the connection was established: StateOpen, even if
//     parentCtx was already canceled, because an established connection stays
//     open.
//   - A canceled parent context takes priority over the error details: it is
//     the only way to tell the user's cancellation apart from our own
//     per-attempt timeout, since both surface as context.DeadlineExceeded.
//     If an error races with cancellation we report StateCanceled, which is
//     deliberate.
//   - ECONNREFUSED is an explicit refusal: StateClosed.
//   - ENETUNREACH or EHOSTUNREACH mean the host or network is unreachable:
//     StateUnreachable.
//   - A net.Error with Timeout() == true covers per-attempt
//     context.DeadlineExceeded and os.ErrDeadlineExceeded: StateTimeout.
//   - Anything else is StateError.
func classifyState(parentCtx context.Context, err error) State {
	if err == nil {
		return StateOpen
	}
	if parentCtx.Err() != nil {
		return StateCanceled
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return StateUnreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}
	return StateError
}
