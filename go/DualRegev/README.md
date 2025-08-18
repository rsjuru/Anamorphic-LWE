# Anamorphic LWE 

---

## Description 

---
This library implements Anamorphic version of the primal Regev cryptosystem. The protocol is presented in paper Fully 
Asymmetric Anamorphic Homomorphic Encryption from LWE by Amit Deo and  Benoıt Libert (2025), in section 4 [p. 19-24]. 

---

## Notes

---
1. Customization: LWE parameters can be modified directly in the code.
--- 
## Requirements

---
To run the program, you need Numpy and Termcolor packages. You can install them using pip:

    pip install numpy termcolor

## Running the Program

---
The lwe file can be executed by first uncommenting the low part of the code and then running:

    python lwe.py

This will run first regular lwe encryption and decryption, then anamorphic encryption and decryption. 

The code also
tests regular encryption and decryption using anamoprhic public and private key and decrypting anamorphic ciphertext
using regular decryption.

The results of the decryption are printed in the terminal (either decryption was successful or not).

## Benchmarking the Program

--- 
To get the benchmarking of key generation, encryption and decryption (regular and anamorphic),
run the following command:

    python benchmarks.py

This will run regular and anamorphic key generation, encryption and decryption 100 times and calculate
average time of each operation in milliseconds. Round amound can be changed by just changing the value
of REPEATS in the code. 

To test for correctness of decryption, run following script:
    
    python test.py

This will run encryption and decryption, default by 100 times, with q values from 2^5 to 2^20 and 
inform the percentage of failing decryptions. 

Code tests regular encryption/decryption, anamorphic encryption/decryption, 
regular encryption/decryption with anamorphic public/private key pair and regular decryption from anamorphic ciphertext. 

