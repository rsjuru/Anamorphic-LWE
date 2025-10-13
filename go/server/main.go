package main

import (
	"anamorphicLWE/measure"
	"anamorphicLWE/scheme"
	"encoding/json"
	"fmt"
	"net/http"
)

// Request represents the expected structure of incoming JSOn requests.
type Request struct {
	Scheme string `json:"scheme"`
	Op     string `json:"op"`
	Lambda int    `json:"lambda"`
	Runs   int    `json:"runs"`
}

// Response respresents the structure of the JSON response returned to the client.
type Response struct {
	Scheme string          `json:"scheme"`
	Op     string          `json:"op"`
	Result measure.Metrics `json:"result"`
}

func main() {
	// Define HTTP handler for POST requests to /run endpoint
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		// Recover from panics and return 500 Internal Server Error instead of crashing
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, fmt.Sprintf("internal server error: %v", err), http.StatusInternalServerError)
			}
		}()

		// Parse JSON body into the Request struct
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Print received parameters for debugging
		fmt.Println(req.Scheme)
		fmt.Println(req.Op)

		// Retriece the cryptographic scheme implementation by name
		s := scheme.GetScheme(req.Scheme)
		if s == nil {
			http.Error(w, "scheme not found: "+req.Scheme, http.StatusBadRequest)
			return
		}

		// Define a variable for the operation function to execute
		var opFunc func(lam int) error
		switch req.Op {
		case "KeyGen":
			opFunc = s.KeyGen // Generate keys
		case "Enc":
			s.KeyGen(req.Lambda) // Generate keys first
			opFunc = s.Enc       // The perform encryption
		case "Dec":
			s.KeyGen(req.Lambda) // Generate keys
			s.Enc(req.Lambda)    // Encrypt a message
			opFunc = s.Dec       // Then decrypt it
		case "AGen":
			opFunc = s.AGen // Generate keys for anamorphic triplet
		case "AEnc":
			s.AGen(req.Lambda) // Generate anamorphic keys first
			opFunc = s.AEnc    // Then perform anamorphic encryption
		case "ADec":
			s.AGen(req.Lambda) // Generate anamorphic keys
			s.AEnc(req.Lambda) // Encrypt anamorphically
			opFunc = s.ADec    // Then decrypt it
		default:
			// Invalid operation name
			http.Error(w, "unknown operation: "+req.Op, http.StatusBadRequest)
			return
		}

		// Ensure that a valid function was assigned
		if opFunc == nil {
			http.Error(w, "operation not implemented: "+req.Op, http.StatusBadRequest)
			return
		}

		// Measure performance metrics for the chosen operation
		result := measure.Measure(opFunc, req.Runs, req.Lambda)
		fmt.Println(result)

		// Encode and send the result back as a JSON response
		json.NewEncoder(w).Encode(Response{
			Scheme: s.Name(),
			Op:     req.Op,
			Result: result,
		})
	})

	// Start the HTTP server on port 8080
	http.ListenAndServe(":8080", nil)
}
