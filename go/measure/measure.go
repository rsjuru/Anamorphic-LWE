package measure

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Stores the performance results of a measured operation.
type Metrics struct {
	AvgLatencyMs   float64 // Average execution time per operation (in milliseconds)
	AvgHeapBytes   uint64  // Average heap memory allocated per run (in bytes)
	AvgAllocsPerOp float64 // Average number of memory allocations per run
}

// Runs a given operation multiple times and collects performance
// metrics such as latency, memory usage, and allocation count.
func Measure(op func(lam int) error, runs int, lam int) Metrics {
	var totalTime float64 // Accumulator for total execution time
	var totalBytes uint64 // Accumulator for total allocated bytes

	for i := 0; i < runs; i++ {
		fmt.Println("Round", i+1) // Print current measurement round

		runtime.GC() // Force garbage collection to reduce noise from prior runs

		// Record memory usage before the operation
		var memStart, memEnd runtime.MemStats
		runtime.ReadMemStats(&memStart)

		// Measure execution time of the operation
		start := time.Now()
		_ = op(lam)
		elapsed := float64(time.Since(start).Milliseconds())

		// Record memory usage afer the operation
		runtime.ReadMemStats(&memEnd)

		// Accumulate execution time and memory usage
		totalTime += elapsed
		totalBytes += memEnd.TotalAlloc - memStart.TotalAlloc
	}

	// Measure average number of allocations per operation
	allocs := testing.AllocsPerRun(runs, func() { _ = op(lam) })

	// Return average performance metrics over all runs
	return Metrics{
		AvgLatencyMs:   totalTime / float64(int64(runs)) / 1000,   // Average latency in seconds
		AvgHeapBytes:   totalBytes / uint64(runs) / (1024 * 1024), // Average heap usage in megabytes
		AvgAllocsPerOp: allocs,                                    // Average allocations per operation
	}
}
