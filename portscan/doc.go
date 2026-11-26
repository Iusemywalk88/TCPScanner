// Package portscan checks the reachability of TCP ports on one or more
// hosts using plain TCP connect scanning built only on the Go standard
// library. It is designed to be embedded into other Go applications and
// depends on no CLI, HTTP framework, database, or message broker.
//
// Error classification is based on syscall error numbers and is intended
// for Linux and macOS.
package portscan
