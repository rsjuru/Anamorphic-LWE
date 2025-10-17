package main

import (
	"anamorphicLWE/scheme"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

// Defines the structure of the JSON message sent to the server.
type Request struct {
	Scheme string `json:"scheme"` // Name of the cryptographic scheme
	Op     string `json:"op"`     // Operation to perform
	Lambda int    `json:"lambda"` // Security parameter lambda
	Runs   int    `json:"runs"`   // Number of times the operation should be executed for measurement
}

// Defines the struture of the JSON message returned by the server.
type Response struct {
	Scheme string `json:"scheme"` // Name of the executed scheme
	Op     string `json:"op"`     // Executed operation
	Result struct {
		AvgLatencyMs   float64 `json:"AvgLatencyMs"`   // Average operation latency in milliseconds
		AvgHeapBytes   uint64  `json:"AvgHeapBytes"`   // Average heap memory usage in bytes
		AvgAllocsPerOp float64 `json:"AvgAllocsPerOp"` // Average number of allocations per operation
	} `json:"result"`
}

func main() {
	// Check that the user provided enough arguments
	if len(os.Args) != 5 {
		fmt.Println("Usage: go run ./client <scheme> <op> <runs> <lambda: 64/128/256>")
		fmt.Println("Example: go run ./client DualRegev AGen 10 128")
		return
	}

	// Parse command-line arguments
	schemeName := os.Args[1]                 // Scheme name
	op := os.Args[2]                         // Operation name
	runs, err1 := strconv.Atoi(os.Args[3])   // Convert run count from string to int
	lambda, err2 := strconv.Atoi(os.Args[4]) // Convert lambda from string to int

	// Validate runs argument
	if err1 != nil {
		fmt.Println("Error: runs must be an integer")
		return
	}

	// Validate lambda argument: must be one of 64, 128 or 256
	if err2 != nil && lambda != 64 && lambda != 128 && lambda != 256 {
		fmt.Println("Error: security parameter must be integer 64, 128 or 256!")
		return
	}

	// Print all registered schemes for reference
	fmt.Println("Registered schemes:")
	for name := range scheme.Schemes {
		fmt.Println("-", name)
	}

	// Create a JSON request object to send to the server
	req := Request{Scheme: schemeName, Op: op, Lambda: lambda, Runs: runs}
	buf, _ := json.Marshal(req) // Serialize request struct into JSON format

	// Send HTTP POST request to local server (default port 8080)
	resp, err := http.Post("http://localhost:8080/run", "application/json", bytes.NewBuffer(buf))
	if err != nil {
		panic(fmt.Errorf("failed to connect to server: %v", err))
	}
	defer resp.Body.Close() // Ensure connection is closed after reading

	// Decode JSON response into the Response struct
	var r Response
	json.NewDecoder(resp.Body).Decode(&r)

	// Print benchmark results in a clear format
	fmt.Printf("Scheme: %s  | Op: %s\n", r.Scheme, r.Op)
	fmt.Printf("Avg Latency: %.5f s\n", r.Result.AvgLatencyMs)
	fmt.Printf("Avg Heap Megabytes: %d \n", r.Result.AvgHeapBytes)
	fmt.Printf("Avg Allocs/Op: %.2f\n", r.Result.AvgAllocsPerOp)
}
