package portscan_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Iusemywalk88/TCPScanner/portscan"
)

// ExampleScanner_Scan demonstrates a full scan. It has no // Output: line,
// so it compiles but is not executed by go test.
func ExampleScanner_Scan() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Println("scanner:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"192.168.1.10", "192.168.1.11"},
		portscan.Range(1, 1000),
	)
	if err != nil {
		switch {
		case errors.Is(err, portscan.ErrInvalidPort):
			fmt.Println("invalid port specification:", err)
		case errors.Is(err, portscan.ErrInvalidTarget):
			fmt.Println("invalid target:", err)
		default:
			fmt.Println("scan:", err)
		}
		return
	}

	for result := range results {
		fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
	}

	if err := ctx.Err(); err != nil {
		fmt.Println("scan stopped early:", err)
	}
}
