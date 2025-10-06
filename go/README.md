# Go Version of Anamorphic Primal and Dual Regev

## Description 


This folder contains Go implementations of the anamorphic primal and dual Regev cryptosystems (based on LWE).

## Notes

1. This library contains Go implementations for four different anamorphic LWE scheme:
    - Public-Key Anamorphic Dual Regev
    - Fully Asymmetric AE from Primal Regev
    - Fully Asymmetric Anamorphic FHE from Dual GSW
    - Trapdoorless Fully Asymmetric AE from Dual Regev
2. /matrix folder contains helper functions for matrix calculation
2. The LWE parameters for each scheme can be modified directly in the source code.

## Requirements

To run the programs, you need:
- Go 1.20+ (or a compatible version installed on your system)

You can verify your Go installation with:

    go version

## Running the Program

### 1. Primal Regev

To run the Primal Regev scheme (from the go directory):

    go run main.go

Make sure that primalregev() is uncommented in the main function to enable the basic functionality.

### 2. Dual Regev

To run the Dual Regev scheme (from the go directory):

    go run main.go

As with primal Regev, ensure that primalregev() is uncommented in the main function. 

### 3. Trapdoorless Dual Regev

To run the Trapdoorless Dual Regev scheme (from the go directory)

    go run main.go

Make sure that asymDR() is uncommented in the main function to enable the basic functionality.

### 4. Dual GSW

To run the Dual GSW (from the go directory)

    go run main.go

Make sure that gsw() is uncommented in the main function to enable the basic functionality.

### Program behaviour 

Running any of the schemes executes the following functionality:
- Key Generation: generates both regular and anamorphic key pairs.
- Encryption: supports both standard and anamorphic encryption. 
- Decryption: decrypts both regular and anamorphic ciphertexts.
- Testing correctness:
    - For Primal Regev and Dual Regev, correctness is checked for a single encryption/decryption operation.
    - For Trapdoorless Dual Regev and Dual GSW, the encryption/decryption process is repeated multiple times (as defined by ITERARIONS) and the program outputs the number of succesfull operations for both regular and anamorphic decryptions.

## Benchmarking the Program

### Primal Regev

To benchmark the primal Regev scheme, run (in the /go directory):

    go run main.go

Make sure that primalregev.runTests() is uncommented in the main function.

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

To benchmark the dual Regev scheme, run from the /go directory:

    go run main.go 

Make sure that dualregev.runTests() is uncommented in the main function.

### Benchmark Behaviour 

The benchmark evaluates both regular and anamorphic:
- Key generation
- Encryption
- Decryption

These operations are executed RUNS times (default: RUNS = 10) with different ciphertext modulus values q, ranging from 2^1 to 2^128.

After all repetitions, the program computes and prints the averages for execution times and sizes (keys, ciphertexts, and decrypted messages), together with the corresponding q values, directly to the terminal. 

### Lambda Benchmark

In addition, the dual Regev scheme can be benchmarked with varying security parameter lambda values, while fixing q = 2^50. Run:

    go run main.go 

Make sure that primalregev.testLambda() is uncommented in the main function.

This test performs the same functionality as runTests(), except that the varying parameter is lambda (from 2^0 to 2^7) instead of q.