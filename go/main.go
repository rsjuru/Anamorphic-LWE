package main

import (
	dgsw "anamorphicLWE/DualGSW"
	DR "anamorphicLWE/DualRegev"
	PR "anamorphicLWE/PrimalRegev"
	tDR "anamorphicLWE/TrapdoorlessDR"
	"anamorphicLWE/matrix"
	"crypto/rand"
	"fmt"
	"time"
)

// Tests trapdoorless Dual Regev encryption scheme
func asymDR() {
	iterations := 100      // number of test runs
	regularSuccess := 0    // counter for standard encryption/decryption success
	anamorphicSuccess := 0 // counter for anamorphic scheme success

	// ------------------------------
	// Test regular LWE encryption/decryption
	// ------------------------------
	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration round:", i+1)

		// Generate secret key (sk) and public key (pk)
		sk, pk := tDR.KGen()
		par := pk.Par

		// Sample plaintext mu in Z_p
		mu := matrix.SampleMatrix(1, 1, par.P)

		// Encrypt mu
		ct := tDR.Enc(pk, mu)

		// Decrypt ciphertext
		dm := tDR.Dec(par, sk, ct)

		// Compare decrypted result with original
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

		// Generate anamorphic key material
		_, apk, dk, tk := tDR.AGen()

		// Sample original message mu and anamorphic message mu_hat
		mu := matrix.SampleMatrix(1, 1, apk.Par.P)
		mu_hat := matrix.SampleMatrix(dk.K, 1, apk.Par.P)

		// Anamorphic encryption
		act := tDR.AEnc(apk, dk, mu[0][0], mu_hat)

		// Anamorphic decryption
		adm := tDR.ADec(apk.Par, dk, tk, act)

		// Compare decrypted mu_hat with original mu_hat
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
	lam := 128

	// Generate standard secret/public key pair
	sk, pk := dgsw.KGen(lam)

	// Generate anamorphic key set (for anamorphic encryption)
	aks := dgsw.AGen(lam)
	apk := aks.Apk // Extract public key from anamorphic key set

	// Counters to track succesfull decryptions
	regularSuccess := 0
	anamorphicSuccess := 0

	iterations := 1000 // Number of messages

	// ------------------ Encryption/Decryption Loop ------------------

	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration number:", i+1)

		// Regular message encryption/decryption
		mu, _ := rand.Int(rand.Reader, pk.Par.P) // Sample random plaintext mu ∈ Zp
		ct := dgsw.Enc(pk, mu)                   // Encrypt using standard scheme
		dm := dgsw.Dec(pk.Par, sk, ct)           // Decrypt ciphertext

		// Check if decryption was correct
		if mu.String() == dm.String() {
			regularSuccess++
		} else {
			fmt.Println("Regular message: ", mu, "and decrypted one: ", dm)
		}

		// Anamorphic message encryption/decryption
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

	t0 := time.Now()
	// Generate key pair
	sk, pk := DR.KGen(64)
	t1 := time.Since(t0).Milliseconds()
	fmt.Println("Time (KGen):", t1)
	par := pk.Params

	// Sample original message
	mu := matrix.SampleMatrix(par.N, 1, par.P)
	fmt.Printf("Original message: %v\n", matrix.Transpose(mu))

	// Regular encrytption/decryption
	t0 = time.Now()
	ct := DR.Enc(pk, mu)
	t1 = time.Since(t0).Milliseconds()
	fmt.Println("Time (Enc):", t1)

	t0 = time.Now()
	dm := DR.Dec(par, sk, ct)
	t1 = time.Since(t0).Milliseconds()
	fmt.Println("Time (Dec):", t1)
	fmt.Printf("Decrypted message: %v\n", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE Decryption works! ✅")
	} else {
		fmt.Println("LWE decryptions fails! ❌")
	}

	// Anamorphic key generation
	t0 = time.Now()
	apk, ask, tk := DR.AGen(64)
	t1 = int64(time.Since(t0).Seconds())
	fmt.Println("Time (AGen):", t1)
	par = apk.Params

	// Sample messages
	mu = matrix.SampleMatrix(par.N, 1, par.P)
	amu := matrix.SampleMatrix(par.N, 1, par.P)
	fmt.Printf("Regular message: %v\n", matrix.Transpose(mu))
	fmt.Printf("Anamorphic message: %v\n", matrix.Transpose(amu))

	// Regular encryption/decryption with anamorphic key pair
	ct = DR.Enc(apk, mu)
	dm = DR.Dec(par, ask, ct)
	fmt.Printf("Original message: %v\n", matrix.Transpose(mu))
	fmt.Printf("Decrypted message: %v\n", matrix.Transpose(mu))
	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("Dual Regev works with anamorphic key pair! ✅")
	} else {
		fmt.Println("Dual Regev fails with anamorphic key pair! ❌")
	}

	// Anamorphic encryption/decryption
	t0 = time.Now()
	act := DR.AEnc(apk, mu, amu)
	t1 = time.Since(t0).Milliseconds()
	fmt.Println("Time (AEnc):", t1)

	t0 = time.Now()
	adm := DR.ADec(apk, tk, ask, act)
	t1 = time.Since(t0).Milliseconds()
	fmt.Println("Time (ADec):", t1)
	fmt.Printf("Original anamorphic message: %v\n", matrix.Transpose(amu))
	fmt.Printf("Decrypted anamorphic message: %v\n", matrix.Transpose(adm))
	if matrix.CompareMatrices(amu, adm) {
		fmt.Println("Anamorphic Dual Regev decryption works! ✅")
	} else {
		fmt.Println("Anamorphic Dual Regev decryption fails! ❌")
	}

	// Test if regular decryption works on anamorphic ciphertext
	dm = DR.Dec(par, ask, act)
	fmt.Printf("Original message in anamorphic ciphertext: %v\n", matrix.Transpose(mu))
	fmt.Printf("Decrypted original message from anamorphic ciphertext: %v\n", matrix.Transpose(dm))

	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("Regular decryption works on anamorphic ciphertext! ✅")
	} else {
		fmt.Println("Regular decryption fails on anamorphic ciphertext! ❌")
	}
}

// Tests anamorphic Primal Regev scheme
func primalregev() {
	// Generate primal key pair
	pk, sk := PR.KGen(64)
	par := pk.Params

	// Sample message
	mu := matrix.SampleMatrix(par.L, 1, par.P)
	fmt.Println("Original message:", matrix.Transpose(mu))

	// Regular encryption/decryption
	ct := PR.Enc(pk, mu)
	dm := PR.Dec(par, sk, ct)
	fmt.Println("Decrypted message:", matrix.Transpose(dm))
	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE decryption works! ✅")
	} else {
		fmt.Println("LWE decryption fails! ❌")
	}

	// Sample anamorphic message
	amu := matrix.SampleMatrix(par.L, 1, par.P)

	// Generate anamorphic key pair
	apk, ask, dk, tk := PR.AGen(64)
	par = apk.Params

	// Encryption/decryption using anamorphic key
	ct = PR.Enc(apk, mu)
	dm = PR.Dec(par, ask, ct)
	fmt.Println("Original Message: ", matrix.Transpose(mu))
	fmt.Println("Decrypted message: ", matrix.Transpose(dm))
	if matrix.CompareMatrices(mu, dm) {
		fmt.Println("LWE decryption works with anamorphic key pair! ✅")
	} else {
		fmt.Println("LWE decryption fails with anamorphic key pair! ❌")
	}

	// Anamorphic encryption/decryption
	act := PR.AEnc(apk, dk, mu, amu)
	adm := PR.ADec(64, tk, act, apk)
	fmt.Println("Original anamorphic message: ", matrix.Transpose(amu))
	fmt.Println("Decrypted anamorphic message: ", matrix.Transpose(adm))
	if matrix.CompareMatrices(amu, adm) {
		fmt.Println("Anamorphic decryption works! ✅")
	} else {
		fmt.Println("Anamorphic decryption fails! ❌")
	}

	// Regular decryption on anamorphic ciphertext
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
	//primalregev() // Run Primal Regev functionality tests
	// dualregev() // Run Dual Regev functionality tests
	//asymDR()      // Run trapdoorless Dual Regev functionality tests
	gsw() // Run Dual GSW functionality tests
	// DR.TestLambda()	// Test different lambda values for Dual Regev
	// DR.RunTests()	// Test different ciphertext modulus values for Dual Regev
	// PR.RunTests() // Test different ciphertext modulus values for Primal Regev
}
