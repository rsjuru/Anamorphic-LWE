package DualRegev

import (
	"anamorphicLWE/matrix"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const LAMLIMIT = 128

const RUNS = 10

// Benchmarks the cryptographic primitives of the scheme
// with respect to varying security parameter lambda.
func TestLambda() {

	// Loop over lam values (powers of 2 up tp LAMLIMIT)
	for i := 0; i < LAMLIMIT; i++ {
		lam := 1 << i // Set lam = 2^i
		// q := new(big.Int).Exp(big.NewInt(2), big.NewInt(50), nil) // Fix q = 2^50

		// Maps to store serialized sizes of keys, ciphertexts, and decrypted messages.
		bytes := map[string][]int{
			"pk":  {},
			"sk":  {},
			"ct":  {},
			"dm":  {},
			"apk": {},
			"ask": {},
			"tk":  {},
		}

		// Maps to store execution times of operations
		times := map[string][]float64{
			"kgen": {},
			"agen": {},
			"enc":  {},
			"aenc": {},
			"dec":  {},
			"adec": {},
		}

		// Repeat each test runs for averaging
		for j := 0; j < RUNS; j++ {
			fmt.Println(j)

			// Standard key generation
			t0 := time.Now()
			sk, pk := KGen(lam)
			t1 := time.Since(t0).Seconds()
			times["kgen"] = append(times["kgen"], t1)

			// Record serailized key sizes
			pkBytes, _ := json.Marshal(pk)
			skBytes, _ := json.Marshal(sk)
			bytes["pk"] = append(bytes["pk"], len(pkBytes))
			bytes["sk"] = append(bytes["sk"], len(skBytes))

			// Standard encryption
			par := pk.Params
			mu := matrix.SampleMatrix(par.N, 1, par.P) // random plaintext
			t0 = time.Now()
			ct := Enc(pk, mu)
			t1 = time.Since(t0).Seconds()
			times["enc"] = append(times["enc"], t1)
			ctBytes, _ := json.Marshal(ct)
			bytes["ct"] = append(bytes["ct"], len(ctBytes))

			// Standard decryption
			t0 = time.Now()
			dm := Dec(par, sk, ct)
			t1 = time.Since(t0).Seconds()
			times["dec"] = append(times["dec"], t1)
			dmBytes, _ := json.Marshal(dm)
			bytes["dm"] = append(bytes["dm"], len(dmBytes))

			// Anamorphic key generation
			t0 = time.Now()
			apk, ask, tk := AGen(lam)
			t1 = time.Since(t0).Seconds()
			times["agen"] = append(times["agen"], t1)
			apkBytes, _ := json.Marshal(apk)
			askBytes, _ := json.Marshal(ask)
			tkBytes, _ := json.Marshal(tk)
			bytes["apk"] = append(bytes["apk"], len(apkBytes))
			bytes["ask"] = append(bytes["ask"], len(askBytes))
			bytes["tk"] = append(bytes["tk"], len(tkBytes))

			// Anamorphic encryption
			par = apk.Params
			amu := matrix.SampleMatrix(par.N, 1, par.P) // additional random plaintext
			t0 = time.Now()
			act := AEnc(apk, mu, amu)
			t1 = time.Since(t0).Seconds()
			times["aenc"] = append(times["aenc"], t1)
			actBytes, _ := json.Marshal(act)
			bytes["act"] = append(bytes["act"], len(actBytes))

			// Anamorphic decryption
			t0 = time.Now()
			adm := ADec(apk, tk, ask, act)
			t1 = time.Since(t0).Seconds()
			times["adec"] = append(times["adec"], t1)
			admBytes, _ := json.Marshal(adm)
			bytes["adm"] = append(bytes["adm"], len(admBytes))
		}

		// Print header for current lam
		fmt.Printf("q = 2^%d = %s\n", i, strconv.Itoa(lam))
		fmt.Println("Average times (seconds):")

		offset := len(times["kgen"]) - RUNS // last RUNS entries

		// Compute and print average times for each operation
		for key, list := range times {
			sum := 0.0
			for j := offset; j < offset+RUNS; j++ {
				sum += list[j]
			}
			avg := sum / float64(RUNS)
			fmt.Printf("  %-5s : %.6f\n", key, avg)
		}

		// Compute and print average serialized sizes
		fmt.Println("Average sizes (bytes):")
		for key, list := range bytes {
			sum := 0
			for j := offset; j < offset+RUNS; j++ {
				sum += list[j]
			}
			avg := float64(sum) / float64(RUNS)
			fmt.Printf("  %-5s : %.2f\n", key, avg)
		}

		fmt.Println("----------------------------------")
	}
}
