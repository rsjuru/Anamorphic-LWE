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

To benchmark the program, follow these steps:

### 1. Start the Server

Run the following command to start the server:

    go run .\server

### 2. Run the Benchmarking on the Client Side

Once the server is running, you can benchmark a specific operation by executing:

    go run .\client <Scheme> <Operation> <Runs> <Lambda>

Parameters:
- Scheme: DualRegev, PrimalRegev, or DualGSW
- Operation: KeyGen, Enc, Dec, AGen, AEnc, or ADec
- Runs: Number of times the server executes the operation
- Lambda: Security parameter - choose one of 64, 128, or 256

Example:

    go run .\client DualRegev AEnc 100 128

### 3. Benchmark Output

The program reports:
- Average latency of the operation (in seconds)
- Average heap memory allocated per operation (in megabytes)
- Number of memory allocations per operation

Note: There is no benchmarking for Trapdoorless Dual Regev!