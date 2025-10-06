# Python Version of anamorphic primal and dual Regev 

## Description 

This folder contains Python implementations of the anamorphic primal and anamorphic dual Regev cryptosystems (based on LWE).

## Notes

1. Primal and dual Regev are implemented in separate folders.
2. The LWE parameters for each scheme can be modified directly in the source code.

## Requirements

To run the programs, you need Numpy and Termcolor packages. You can install them using pip:

    pip install numpy termcolor

## Running the Programs

### Primal Regev

Run the primal Regev scheme from the /PrimalRegev directory with:

    python lwe.py

This executes both the regular and the anamorphic versions of the primal Regev scheme and tests the correctness of decryption.
The program outputs the messages and comparison results to the terminal.

### Dual Regev

Run the dual Regev scheme from the /DualRegev directory with:

    python dualRegev.py

The dual Regev implementation provides the same functionality as the primal Regev scheme. 

### Trapdoorless Dual Regev

Run the trapdoorless Dual Regev scheme form the /Trapdoorless DualRegev directory with:

    python AME.py

This executes both the regular and anamorphic versions of the Trapdoorless Dual Regev scheme ITERATIONS times and in the end informs how many of both the regular and anamorphic decryptions were succesfull. 

### Dual GSW

Run the Dual GSW scheme from the /DualGSW directory with:

    python GSW.py

The Dual GSW implementation provides the same functionality as the Primal Regev scheme.

## Benchmarking the Programs

### Benchmarking Performance (for Primal and Dual Regev)

To benchmark key generation, encryption, and decryption (both regular and anamorphic), run (in either /primalRegev or /dualRegev):

    python benchmarks.py

By default, each operation (key generation, encryption and, decryption) is repeated 100 times, and the script reports the average execution time (in milliseconds). 
You can change the number of repetitions by modifying the value of REPEATS in the code. 

### Testing Correctness (form Primal and Dual Regev) 

To test the correctness of decryption, run (in either /primalRegev or /dualRegev):

    python test.py

This script runs encryption and decryption 100 times by default for ciphertext modulus values q = 2^5 to 2^40, and reports the percentage of failed decryption.

The test cover:

- Regular encryption/decryption
- Anamorphic encryption/decryption
- Regular encryption/decryption with an anamorphic public/private key pair
- Regular decryption from an anamorpic ciphertext
