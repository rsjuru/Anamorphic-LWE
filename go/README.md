# Go Version of Anamorphic Primal and Dual Regev

## Description 


This folder contains Go implementations of the anamorphic primal and dual Regev cryptosystems (based on LWE).

## Notes

1. Primal and dual Regev schemes are implemented in separate folders.
2. The LWE parameters for each scheme can be modified directly in the source code.

## Requirements

To run the programs, you need:
- Go 1.20+ (or a compatible version installed on your system)

You can verify your Go installation with:

    go version

## Running the Program

### Primal Regev

Run the primal Regev scheme from the /primalRegev directory:

    go run main.go

Make sure that functionality() is uncommented in the main function to enable the basic functionality.

### Dual Regev

Run the dual Regev scheme from the /dualRegev directory:

    go run main.go

As with primal Regev, ensure that functionality() is uncommented in the main function. 

### Program behaviour 

Running either implementation executes the basic functionality of the scheme, including:
- Regular and anamorphic key generation 
- Encryption and decryption
- Testing correctness of decryption

## Benchmarking the Program

### Primal Regev

To benchmark the primal Regev scheme, run (in /primalRegev):

    go run main.go test.go

Make sure that runTests() is uncommented in the main function.

The benchmark performs both regular and anamorphic:
- Key generation
- Encryption
- Decryption

These operations are executed RUNS times (default: RUNS = 10) for different ciphertext modulus values q from 2^0 to 2^64.

For each run, the program measures:
- Execution times of all operations
- Sizes of keys, ciphertexts, and decrypted messages

After all repetitions, the program computes and prints the averages for both times and sizes, along with the corresponding q value, directly to the terminal. 

### Dual Regev

To benchmark the dual Regev scheme, run from the /dualRegev directory:

    go run main.go test.go

Make sure that runTests() is uncommented in the main function.

### Benchmark Behaviour 

The benchmark evaluates both regular and anamorphic:
- Key generation
- Encryption
- Decryption

These operations are executed RUNS times (default: RUNS = 10) with different ciphertext modulus values q, ranging from 2^1 to 2^128.

After all repetitions, the program computes and prints the averages for execution times and sizes (keys, ciphertexts, and decrypted messages), together with the corresponding q values, directly to the terminal. 

### Lambda Benchmark

In addition, the dual Regev scheme can be benchmarked with varying security parameter lambda values, while fixing q = 2^50. Run:

    go run main.go testLambda.go

Make sure that testLambda() is uncommented in the main function.

This test performs the same functionality as runTests(), except that the varying parameter is lambda (from 2^0 to 2^7) instead of q.