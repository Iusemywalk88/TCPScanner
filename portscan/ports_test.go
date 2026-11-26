package portscan

import (
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

func TestNormalizePorts(t *testing.T) {
	tests := []struct {
		name string
		spec PortSpec
		want []uint16
	}{
		{"single port", Ports(80), seq(80, 80)},
		{"range", Range(1, 10), seq(1, 10)},
		{"list sorted", Ports(80, 443, 22), []uint16{22, 80, 443}},
		{"union", Union(Range(1, 3), Ports(80), Range(10, 12)), []uint16{1, 2, 3, 10, 11, 12, 80}},
		{"duplicate ports", Ports(80, 80, 443), []uint16{80, 443}},
		{"overlapping ranges", Union(Range(1, 10), Range(5, 15)), seq(1, 15)},
		{"adjacent ranges", Union(Range(1, 10), Range(11, 20)), seq(1, 20)},
		{"nested ranges", Union(Range(1, 100), Range(20, 30)), seq(1, 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePorts(tt.spec)
			if err != nil {
				t.Fatalf("normalizePorts(%v) error: %v", tt.spec, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("normalizePorts(%v) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestNormalizePortsFullRange(t *testing.T) {
	ports, err := normalizePorts(Range(1, 65535))
	if err != nil {
		t.Fatalf("normalizePorts(Range(1, 65535)) error: %v", err)
	}
	if len(ports) != 65535 {
		t.Fatalf("len = %d, want 65535", len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("ends = %d..%d, want 1..65535", ports[0], ports[len(ports)-1])
	}
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[i-1]+1 {
			t.Fatalf("not ascending at index %d: %d -> %d", i-1, ports[i-1], ports[i])
		}
	}
}

func TestNormalizePortsErrors(t *testing.T) {
	tests := []struct {
		name string
		spec PortSpec
	}{
		{"port 0", Ports(0)},
		{"port 65536", Ports(65536)},
		{"negative port", Ports(-1)},
		{"reversed range", Range(1000, 1)},
		{"empty list", Ports()},
		{"zero value", PortSpec{}},
		{"empty union", Union()},
		{"union with invalid part", Union(Range(1, 10), Ports(70000))},
		{"huge range zero to max", Range(0, 1<<62)},
		{"huge range to max int", Range(1, math.MaxInt64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := normalizePorts(tt.spec)
			if err == nil {
				t.Fatalf("normalizePorts(%v) = %v, want error", tt.spec, ports)
			}
			if !errors.Is(err, ErrInvalidPort) {
				t.Fatalf("normalizePorts(%v) error = %v, want to wrap ErrInvalidPort", tt.spec, err)
			}
		})
	}
}

func TestNormalizePortsHugeRangePrompt(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := normalizePorts(Range(0, 1<<62))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidPort) {
			t.Fatalf("error = %v, want ErrInvalidPort", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normalizePorts did not return promptly for Range(0, 1<<62)")
	}
}

// seq returns the ascending port list [from, to].
func seq(from, to int) []uint16 {
	if from > to {
		return nil
	}
	out := make([]uint16, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, uint16(i))
	}
	return out
}
