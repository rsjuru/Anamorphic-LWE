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

## Testing the Program

--- 
To run tests for suitable q value, you can execute the following command:

    python test.py

This will run regular and anamorphic encryption/decryption process defined amount of times (default 100 times) and gives
result of how many times decryption fails. 

Rounds are run with different q values from 2<sup>5</sup> to 2<sup>20</sup>. The amount of the rounds can be changed
directly at the code. 
