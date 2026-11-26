// Package portscan checks the reachability of TCP ports on one or more
// hosts using plain TCP connect scanning built only on the Go standard
// library. It is designed to be embedded into other Go applications and
// depends on no CLI, HTTP framework, database, or message broker.
//
// # Usage
//
//	scanner, err := portscan.New(
//	    portscan.WithConcurrency(100),
//	    portscan.WithConnectTimeout(500 * time.Millisecond),
//	)
//	if err != nil {
//	    return err
//	}
//
//	results, err := scanner.Scan(
//	    ctx,
//	    []string{"192.168.1.10", "192.168.1.11"},
//	    portscan.Range(1, 1000),
//	)
//	if err != nil {
//	    return err
//	}
//
//	for result := range results {
//	    fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
//	}
//
// # Limitations
//
//   - Only TCP connect scanning is supported: no SYN or UDP scanning, raw
//     sockets, OS fingerprinting, or firewall evasion.
//   - Error classification is based on syscall error numbers and is intended
//     for Linux and macOS.
//   - Hosts are resolved sequentially and scanned in order, so a single
//     target receives up to the configured number of simultaneous dials.
//   - The concurrency limit applies to a single Scan call.
//   - Results are not ordered.
package portscan
