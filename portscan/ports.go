package portscan

import (
	"errors"
	"fmt"
	"sort"
)

// PortSpec is an immutable specification of TCP ports, built with Range,
// Ports, and Union. Invalid values are retained and reported by Scan;
// duplicate and overlapping ranges are collapsed when the spec is normalized.
// The zero value is an empty specification.
type PortSpec struct {
	intervals []interval
}

// interval is a single inclusive port range [from, to].
type interval struct {
	from, to int
}

// Range returns a PortSpec covering the inclusive range [from, to]. Invalid
// values are recorded and reported by Scan. Overlapping and adjacent ranges
// are merged when the spec is normalized.
func Range(from, to int) PortSpec {
	return PortSpec{intervals: []interval{{from: from, to: to}}}
}

// Ports returns a PortSpec covering the given individual ports. Duplicate
// ports are collapsed when the spec is normalized.
func Ports(ports ...int) PortSpec {
	ivs := make([]interval, len(ports))
	for i, p := range ports {
		ivs[i] = interval{from: p, to: p}
	}
	return PortSpec{intervals: ivs}
}

// Union returns a PortSpec combining all the given specs. Invalid values in
// any part are reported by Scan; duplicate and overlapping ranges are
// collapsed when the spec is normalized.
func Union(specs ...PortSpec) PortSpec {
	var n int
	for _, s := range specs {
		n += len(s.intervals)
	}
	if n == 0 {
		return PortSpec{}
	}
	ivs := make([]interval, 0, n)
	for _, s := range specs {
		ivs = append(ivs, s.intervals...)
	}
	return PortSpec{intervals: ivs}
}

// normalizePorts validates spec, merges overlapping and adjacent ranges, and
// expands the result into a sorted, de-duplicated list of ports. It returns
// nil and an error wrapping ErrInvalidPort if spec is empty or invalid.
func normalizePorts(spec PortSpec) ([]uint16, error) {
	if len(spec.intervals) == 0 {
		return nil, fmt.Errorf("%w: empty port list", ErrInvalidPort)
	}

	var errs []error
	for _, iv := range spec.intervals {
		errs = append(errs, validateInterval(iv)...)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return expandIntervals(mergeIntervals(spec.intervals)), nil
}

// validateInterval reports every invalid property of iv, each wrapping
// ErrInvalidPort. It never iterates over the covered ports, so arbitrarily
// large ranges are validated in constant time.
func validateInterval(iv interval) []error {
	if iv.from > iv.to {
		return []error{fmt.Errorf("%w: range %d-%d is reversed (from > to)", ErrInvalidPort, iv.from, iv.to)}
	}
	var errs []error
	if iv.from < 1 {
		errs = append(errs, fmt.Errorf("%w: port %d is outside [1, 65535]", ErrInvalidPort, iv.from))
	}
	if iv.to > 65535 {
		errs = append(errs, fmt.Errorf("%w: port %d is outside [1, 65535]", ErrInvalidPort, iv.to))
	}
	return errs
}

// mergeIntervals returns a sorted copy of ivs with overlapping and adjacent
// ranges merged. It does not modify ivs.
func mergeIntervals(ivs []interval) []interval {
	sorted := make([]interval, len(ivs))
	copy(sorted, ivs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].from != sorted[j].from {
			return sorted[i].from < sorted[j].from
		}
		return sorted[i].to < sorted[j].to
	})

	merged := make([]interval, 0, len(sorted))
	for _, iv := range sorted {
		if len(merged) == 0 {
			merged = append(merged, iv)
			continue
		}
		last := &merged[len(merged)-1]
		if iv.from <= last.to+1 {
			if iv.to > last.to {
				last.to = iv.to
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

// expandIntervals expands non-overlapping ranges into a sorted slice of
// ports. The result has at most 65535 elements.
func expandIntervals(ivs []interval) []uint16 {
	var n int
	for _, iv := range ivs {
		n += iv.to - iv.from + 1
	}
	ports := make([]uint16, 0, n)
	for _, iv := range ivs {
		for p := iv.from; p <= iv.to; p++ {
			ports = append(ports, uint16(p))
		}
	}
	return ports
}
