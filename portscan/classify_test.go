package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestClassifyState(t *testing.T) {
	liveCtx := context.Background()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want State
	}{
		// nil error is open regardless of the parent context.
		{"nil live", liveCtx, nil, StateOpen},
		{"nil canceled", canceledCtx, nil, StateOpen},

		// closed.
		{"econnrefused", liveCtx, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, StateClosed},
		{"econnrefused wrapped", liveCtx, fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}), StateClosed},

		// unreachable.
		{"enetunreach", liveCtx, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, StateUnreachable},
		{"ehostunreach", liveCtx, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, StateUnreachable},
		{"enetunreach wrapped", liveCtx, fmt.Errorf("dial: %w", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}), StateUnreachable},

		// timeout (parent context alive).
		{"deadline exceeded live", liveCtx, context.DeadlineExceeded, StateTimeout},
		{"os deadline exceeded", liveCtx, os.ErrDeadlineExceeded, StateTimeout},
		{"net op timeout", liveCtx, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, StateTimeout},
		{"etimedout", liveCtx, syscall.ETIMEDOUT, StateTimeout},

		// canceled (parent context done).
		{"canceled parent", canceledCtx, context.Canceled, StateCanceled},
		{"deadline parent", deadlineCtx, context.DeadlineExceeded, StateCanceled},

		// generic.
		{"boom", liveCtx, errors.New("boom"), StateError},
		{"eaddrnotavail", liveCtx, syscall.EADDRNOTAVAIL, StateError},
		{"emfile", liveCtx, syscall.EMFILE, StateError},

		// proves there is no text matching.
		{"text connection refused", liveCtx, errors.New("connection refused"), StateError},
		{"text i/o timeout", liveCtx, errors.New("i/o timeout"), StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyState(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("classifyState(%v, %v) = %v, want %v", tt.ctx.Err(), tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyStateIntegration(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("real kernel error classification only runs on linux and darwin")
	}

	ctx := context.Background()
	d := &net.Dialer{}

	t.Run("closed", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}

		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			t.Fatal("dial succeeded, want refusal")
		}
		if got := classifyState(ctx, err); got != StateClosed {
			t.Fatalf("classifyState = %v, want %v (closed), err = %v", got, StateClosed, err)
		}
	})

	t.Run("open", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		addr := l.Addr().String()

		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Close()
		if got := classifyState(ctx, err); got != StateOpen {
			t.Fatalf("classifyState = %v, want %v (open)", got, StateOpen)
		}
	})
}
