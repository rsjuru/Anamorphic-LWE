package main

import (
	DR "anamorphicLWE/DualRegev"
	PR "anamorphicLWE/PrimalRegev"
	tDR "anamorphicLWE/TrapdoorlessDR"
	dgsw "anamorphicLWE/dualGSW"
	"anamorphicLWE/matrix"
	"crypto/rand"
	"fmt"
	"math/big"
)

func asymDR() {
	iterations := 100      // number of test runs
	regularSuccess := 0    // counter for standard encryption/decryption success
	anamorphicSuccess := 0 // counter for anamorphic scheme success

	// ------------------------------
	// Test regular LWE encryption/decryption
	// ------------------------------
	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration round:", i+1)

		// 1. Generate secret key (sk) and public key (pk)
		sk, pk := tDR.KGen()
		par := pk.Par

		// 2. Sample plaintext mu in Z_p
		mu := matrix.SampleMatrix(1, 1, par.P)

		// 3. Encrypt mu
		ct := tDR.Enc(pk, mu)

		// 4. Decrypt ciphertext
		dm := tDR.Dec(par, sk, ct)

		// 5. Compare decrypted result with original
		if mu[0][0].String() == dm.String() {
			regularSuccess++
		} else {
			fmt.Println("Original message:", mu[0][0])
			fmt.Println("Decrypted message:", dm)
		}
	}

	// ------------------------------
	// Test anamorphic encryption/decryption
	// ------------------------------
	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration round:", i+1)

		// 1. Generate anamorphic key material
		_, apk, dk, tk := tDR.AGen()

		// 2. Sample original message mu and anamorphic message mu_hat
		mu := matrix.SampleMatrix(1, 1, apk.Par.P)
		mu_hat := matrix.SampleMatrix(dk.K, 1, apk.Par.P)

		// 3. Anamorphic encryption
		act := tDR.AEnc(apk, dk, mu[0][0], mu_hat)

		// 4. Anamorphic decryption
		adm := tDR.ADec(apk.Par, dk, tk, act)

		// 5. Compare decrypted mu_hat with original mu_hat
		if matrix.CompareMatrices(mu_hat, adm) {
			anamorphicSuccess++
		} else {
			fmt.Println("Original anamorphic message:", matrix.Transpose(mu_hat))
			fmt.Println("Decrypted anamorphic message:", matrix.Transpose(adm))
		}
	}

	// ------------------------------
	// Report results
	// ------------------------------
	fmt.Println(regularSuccess, "/", iterations, "regular decryptions succeeded!")
	fmt.Println(anamorphicSuccess, "/", iterations, "anamorphic decryptions succeeded!")

}

func gsw() {
	// ------------------ Initialization ------------------

	// Set modulus q = 2^15
	q := new(big.Int).Lsh(big.NewInt(1), 15)

	// Generate standard secret/public key pair
	sk, pk := dgsw.KGen(q)

	// Generate anamorphic key set (for anamorphic encryption)
	aks := dgsw.AGen(q)
	apk := aks.Apk // Extract public key from anamorphic key set

	// Counters to track succesfull decryptions
	regularSuccess := 0
	anamorphicSuccess := 0

	iterations := 1000 // Number of messages

	// ------------------ Encryption/Decryption Loop ------------------

	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration number:", i+1)

		// 1. Regular message encryption/decryption
		mu, _ := rand.Int(rand.Reader, pk.Par.P) // Sample random plaintext mu ∈ Zp
		ct := dgsw.Enc(pk, mu)                   // Encrypt using standard scheme
		dm := dgsw.Dec(pk.Par, sk, ct)           // Decrypt ciphertext

		// Check if decryption was correct
		if mu.String() == dm.String() {
			regularSuccess++
		} else {
			fmt.Println("Regular message: ", mu, "and decrypted one: ", dm)
		}

		// 2. Anamorphic message encryption/decryption
		muHat, _ := rand.Int(rand.Reader, apk.Par.P) // Sample random plaintext for anamorphic encryption

		act := dgsw.AEnc(apk, aks.Dk, mu, muHat)                // Encrypt message using anamorphic scheme
		adm := dgsw.ADec(apk.Par, aks.Dk, aks.Tk, aks.Ask, act) // Decrypt ciphertext

		// Check if anamorphic decryption was correct
		if muHat.String() == adm.String() {
			anamorphicSuccess++
		} else {
			fmt.Println("Anamorphic message:", muHat, "and decrypted message: ", adm)
		}
	}

	// ------------------ Print Results ------------------

	fmt.Printf("%d/%d regular decryptions succeeded!\n", regularSuccess, iterations)
	fmt.Printf("%d/%d anamorphic decryptions succeeded!\n", anamorphicSuccess, iterations)
}

func dualregev() {
	q := new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)
	sk, pk := DR.KGen(q)
	par := pk.Params
	mu := matrix.SampleMatrix(par.N, 1, par.P)
	fmt.Printf("Original message: %v\n", matrix.Transpose(mu))

	ct := DR.Enc(pk, mu)
	dm := DR.Dec(par, sk, ct)
	fmt.Printf("Decrypted message: %v\n", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE Decryption works! ✅")
	} else {
		fmt.Println("LWE decryptions fails! ❌")
	}

	apk, ask, tk := DR.AGen(q)
	par = apk.Params
	mu = matrix.SampleMatrix(par.N, 1, par.P)
	amu := matrix.SampleMatrix(par.N, 1, par.P)

	fmt.Printf("Regular message: %v\n", matrix.Transpose(mu))
	fmt.Printf("Anamorphic message: %v\n", matrix.Transpose(amu))

	ct = DR.Enc(apk, mu)
	dm = DR.Dec(par, ask, ct)

	fmt.Printf("Original message: %v\n", matrix.Transpose(mu))
	fmt.Printf("Decrypted message: %v\n", matrix.Transpose(mu))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("Dual Regev works with anamorphic key pair! ✅")
	} else {
		fmt.Println("Dual Regev fails with anamorphic key pair! ❌")
	}

	act := DR.AEnc(apk, mu, amu)
	adm := DR.ADec(apk, tk, ask, act)

	fmt.Printf("Original anamorphic message: %v\n", matrix.Transpose(amu))
	fmt.Printf("Decrypted anamorphic message: %v\n", matrix.Transpose(adm))

	if matrix.CompareMatrices(amu, adm) {
		fmt.Println("Anamorphic Dual Regev decryption works! ✅")
	} else {
		fmt.Println("Anamorphic Dual Regev decryption fails! ❌")
	}

	dm = DR.Dec(par, ask, act)

	fmt.Printf("Original message in anamorphic ciphertext: %v\n", matrix.Transpose(mu))
	fmt.Printf("Decrypted original message from anamorphic ciphertext: %v\n", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("Regular decryption works on anamorphic ciphertext! ✅")
	} else {
		fmt.Println("Regular decryption fails on anamorphic ciphertext! ❌")
	}
}

func primalregev() {
	q := new(big.Int).Exp(big.NewInt(2), big.NewInt(16), nil)
	pk, sk := PR.KGen(q)
	par := pk.Params
	mu := matrix.SampleMatrix(par.L, 1, par.P)

	fmt.Println("Original message:", matrix.Transpose(mu))

	ct := PR.Enc(pk, mu)
	dm := PR.Dec(par, sk, ct)

	fmt.Println("Decrypted message:", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE decryption works! ✅")
	} else {
		fmt.Println("LWE decryption fails! ❌")
	}

	amu := matrix.SampleMatrix(par.L, 1, par.P)
	apk, ask, dk, tk := PR.AGen(q)
	par = apk.Params
	ct = PR.Enc(apk, mu)
	dm = PR.Dec(par, ask, ct)
	fmt.Println("Original Message: ", matrix.Transpose(mu))
	fmt.Println("Decrypted message: ", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE decryption works with anamorphic key pair! ✅")
	} else {
		fmt.Println("LWE decryption fails with anamorphic key pair! ❌")
	}

	act := PR.AEnc(apk, dk, mu, amu)
	adm := PR.ADec(tk, act, apk)

	fmt.Println("Original anamorphic message: ", matrix.Transpose(amu))
	fmt.Println("Decrypted anamorphic message: ", matrix.Transpose(adm))

	if matrix.CompareMatrices(amu, adm) {
		fmt.Println("Anamorphic decryption works! ✅")
	} else {
		fmt.Println("Anamorphic decryption fails! ❌")
	}

	dm = PR.Dec(par, ask, act)

	fmt.Println("Original message: ", matrix.Transpose(mu))
	fmt.Println("Original message decrypted from anamorphic ciphertext: ", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("Regular decryption works with anamorphic ciphertext! ✅")
	} else {
		fmt.Println("Regular decryption fails with anamorphic ciphertext! ❌")
	}
}

func main() {
	primalregev()
}
