package portscan

import "testing"

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateOpen, "open"},
		{StateClosed, "closed"},
		{StateTimeout, "timeout"},
		{StateUnreachable, "unreachable"},
		{StateCanceled, "canceled"},
		{StateError, "error"},
		{State(0), "invalid"},
		{State(7), "invalid"},
		{State(255), "invalid"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
