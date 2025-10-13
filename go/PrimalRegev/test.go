package PrimalRegev

import (
	"anamorphicLWE/matrix"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

const RUNS = 10 // Number of repeptitions per q value

const QLIMIT = 65 //	Maximum exponent for q

// Benchmarks the regular and anamorphic encryption schemes
func RunTests() {

	// Print table header
	fmt.Printf("%-10s %-10s %-10s %-10s %-10s %-10s\n", "i", "q=2^i", "avg_kgen", "avg_pkB", "avg_skB", "avg_enc")

	// Loop over q = 2^i, for i = 0..QLIMIT
	for i := 1; i < QLIMIT; i++ {
		i64 := int64(i)
		q := new(big.Int).Exp(big.NewInt(2), big.NewInt(i64), nil) // q = 2^i

		// Maps to store serialized sizes of various keys, ciphertexts, and decrypted messages
		bytes := map[string][]int{
			"pk":  {},
			"sk":  {},
			"ct":  {},
			"dm":  {},
			"apk": {},
			"ask": {},
			"dk":  {},
			"tk":  {},
			"act": {},
			"adm": {},
		}

		// Maps to store execution times of each cryptographic operation
		times := map[string][]float64{
			"kgen": {},
			"agen": {},
			"enc":  {},
			"aenc": {},
			"dec":  {},
			"adec": {},
		}

		// Repeat each test RUNS times for averaging
		for j := 0; j < RUNS; j++ {
			// Standard key generation
			t0 := time.Now()
			pk, sk := KGen(64)
			t1 := time.Since(t0).Seconds()
			times["kgen"] = append(times["kgen"], t1)

			// Record serialized key sizes
			pkBytes, _ := json.Marshal(pk)
			skBytes, _ := json.Marshal(sk)
			bytes["pk"] = append(bytes["pk"], len(pkBytes))
			bytes["sk"] = append(bytes["sk"], len(skBytes))

			// Standard encryption
			par := pk.Params
			mu := matrix.SampleMatrix(par.L, 1, par.P) // generate random plaintext
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
			apk, ask, dk, tk := AGen(64)
			t1 = time.Since(t0).Seconds()
			times["agen"] = append(times["agen"], t1)
			apkBytes, _ := json.Marshal(apk)
			askBytes, _ := json.Marshal(ask)
			dkBytes, _ := json.Marshal(dk)
			tkBytes, _ := json.Marshal(tk)
			bytes["apk"] = append(bytes["apk"], len(apkBytes))
			bytes["ask"] = append(bytes["ask"], len(askBytes))
			bytes["dk"] = append(bytes["dk"], len(dkBytes))
			bytes["tk"] = append(bytes["tk"], len(tkBytes))

			// Anamorphic encryption
			par = apk.Params
			smu := matrix.SampleMatrix(par.L, 1, par.P) // covert plaintext
			t0 = time.Now()
			act := AEnc(apk, dk, mu, smu)
			t1 = time.Since(t0).Seconds()
			times["aenc"] = append(times["aenc"], t1)
			actBytes, _ := json.Marshal(act)
			bytes["act"] = append(bytes["act"], len(actBytes))

			// Anamorphic decryption
			t0 = time.Now()
			adm := ADec(64, tk, act, apk)
			t1 = time.Since(t0).Seconds()
			times["adec"] = append(times["adec"], t1)
			admBytes, _ := json.Marshal(adm)
			bytes["adm"] = append(bytes["adm"], len(admBytes))
		}

		// === Summary for current q value ===
		fmt.Printf("q = 2^%d = %s\n", i, q.String())
		fmt.Println("Average times (seconds):")

		offset := i * RUNS // offset for averaging last RUNS measurements

		// Compute and print average times for each operation
		for key, list := range times {
			sum := 0.0
			for j := offset; j < offset+RUNS; j++ {
				sum += list[j]
			}
			avg := sum / float64(RUNS)
			fmt.Printf("  %-5s : %.6f\n", key, avg)
		}

		// Compute and print average seralized sizes
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
