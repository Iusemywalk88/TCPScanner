package portscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// job is a single unit of work handed to a worker. For a resolved target ip
// and port are set; for a failed resolution resolveErr and elapsed carry the
// error and its duration, and ip/port are zero.
type job struct {
	host       string
	ip         netip.Addr
	port       uint16
	resolveErr error
	elapsed    time.Duration
}

// run scans every target×port pair and streams results to the returned
// channel. Inputs must already be validated and normalized.
//
// The caller must either drain the channel to completion or cancel ctx,
// otherwise the scan goroutines leak. The order of results is unspecified.
// cfg.concurrency limits the number of simultaneous dials for this call only.
func run(ctx context.Context, cfg config, targets []target, ports []uint16) <-chan Result {
	// out is written only by workers and closed only by the closer goroutine.
	out := make(chan Result, cfg.concurrency)
	// jobs is unbuffered; only the producer sends on it and closes it.
	jobs := make(chan job)

	var wg sync.WaitGroup
	wg.Add(cfg.concurrency)
	for i := 0; i < cfg.concurrency; i++ {
		go func() {
			defer wg.Done()
			worker(ctx, cfg, jobs, out)
		}()
	}

	// Closer goroutine owns the close of out: it fires only after every worker
	// has finished, so no worker can ever send on a closed channel.
	go func() {
		wg.Wait()
		close(out)
	}()

	// Producer goroutine owns jobs: it is the only sender and the only closer,
	// so closing it signals "no more work" to all workers.
	go func() {
		defer close(jobs)
		produce(ctx, cfg, targets, ports, jobs)
	}()

	return out
}

// produce resolves targets sequentially and streams (ip, port) jobs. It stops
// as soon as ctx is done.
func produce(ctx context.Context, cfg config, targets []target, ports []uint16, jobs chan<- job) {
	set := make(ipSet)
	for _, t := range targets {
		start := time.Now()
		ips, err := resolveTarget(ctx, cfg.resolver, t)
		elapsed := time.Since(start)
		if err != nil {
			// A canceled ctx must stop the scan, not emit a resolve Result.
			if ctx.Err() != nil {
				return
			}
			// A real resolution failure becomes a single error result.
			// select: respect cancellation even while handing off to a worker.
			select {
			case jobs <- job{host: t.host, resolveErr: err, elapsed: elapsed}:
			case <-ctx.Done():
				return
			}
			continue
		}
		for _, ip := range ips {
			if !set.add(ip) {
				continue
			}
			for _, port := range ports {
				// select: the producer owns jobs and must stop sending after
				// cancellation, which ctx.Done() signals.
				select {
				case jobs <- job{host: t.host, ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// worker drains jobs until it is closed. A job picked up after cancellation
// was never started and produces no result.
func worker(ctx context.Context, cfg config, jobs <-chan job, out chan<- Result) {
	for j := range jobs {
		// Never start a job after cancellation: drop it silently.
		if ctx.Err() != nil {
			continue
		}
		if j.resolveErr != nil {
			send(ctx, out, Result{
				Host:     j.host,
				State:    StateError,
				Err:      j.resolveErr,
				Duration: j.elapsed,
			})
			continue
		}

		dctx, cancel := context.WithTimeout(ctx, cfg.connectTimeout)
		start := time.Now()
		conn, err := cfg.dialer.DialContext(dctx, "tcp", net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port))))
		duration := time.Since(start)
		cancel()

		if err == nil {
			// Always close a successful connection; a close error is moot.
			conn.Close()
		}

		r := Result{
			Host:     j.host,
			IP:       j.ip,
			Port:     j.port,
			State:    classifyState(ctx, err),
			Duration: duration,
		}
		if err != nil {
			r.Err = err
		}
		send(ctx, out, r)
	}
}

// send delivers r to out. While ctx is alive it applies backpressure (no
// loss); after cancellation it is best effort.
func send(ctx context.Context, out chan<- Result, r Result) {
	// First a non-blocking send so a draining reader still receives results
	// even after cancellation.
	select {
	case out <- r:
		return
	default:
	}
	// Otherwise block for the reader, but give up if the context is done.
	select {
	case out <- r:
	case <-ctx.Done():
	}
}
