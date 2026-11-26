package portscan

import "errors"

// Sentinel errors returned by the package. Callers detect them with
// errors.Is.
var (
	// ErrInvalidTarget indicates that a target is empty or syntactically
	// invalid. It is returned by Scan.
	ErrInvalidTarget = errors.New("invalid target")

	// ErrInvalidPort indicates an invalid port specification: port 0, a
	// port above 65535, a reversed range, or an empty port list. It is
	// returned by Scan.
	ErrInvalidPort = errors.New("invalid port")

	// ErrInvalidOption indicates an invalid option passed to New.
	ErrInvalidOption = errors.New("invalid option")

	// ErrResolve indicates that a DNS name could not be resolved. It
	// appears in Result.Err, not as a Scan error.
	ErrResolve = errors.New("cannot resolve host")
)
