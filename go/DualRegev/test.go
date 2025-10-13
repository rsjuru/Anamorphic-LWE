package DualRegev

import (
	"anamorphicLWE/matrix"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

const QLIMIT = 129

// Benchmarks and measures sizes for anamorphic dual Regev scheme.
func RunTests() {

	for i := 1; i < QLIMIT; i++ {
		i64 := int64(i)
		// Generate q = 2^i
		q := new(big.Int).Exp(big.NewInt(2), big.NewInt(i64), nil)

		// Maps to store byte sizes of keys, ciphertexts, and decrypted messages
		bytes := map[string][]int{
			"pk":  {},
			"sk":  {},
			"ct":  {},
			"dm":  {},
			"apk": {},
			"ask": {},
			"tk":  {},
			"act": {},
			"adm": {},
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

		for j := 0; j < RUNS; j++ {
			// ------------------ Key Generation ------------------
			t0 := time.Now()
			sk, pk := KGen(64) // regular keygen
			t1 := time.Since(t0).Seconds()
			times["kgen"] = append(times["kgen"], t1)

			// Recorded serialized sizes
			pkBytes, _ := json.Marshal(pk)
			skBytes, _ := json.Marshal(sk)
			bytes["pk"] = append(bytes["pk"], len(pkBytes))
			bytes["sk"] = append(bytes["sk"], len(skBytes))

			// ------------------ Encryption ------------------
			par := pk.Params
			mu := matrix.SampleMatrix(par.N, 1, par.P) // plaintext
			t0 = time.Now()
			ct := Enc(pk, mu)
			t1 = time.Since(t0).Seconds()
			times["enc"] = append(times["enc"], t1)

			ctBytes, _ := json.Marshal(ct)
			bytes["ct"] = append(bytes["ct"], len(ctBytes))

			// ------------------ Decryption ------------------
			t0 = time.Now()
			dm := Dec(par, sk, ct)
			t1 = time.Since(t0).Seconds()
			times["dec"] = append(times["dec"], t1)

			dmBytes, _ := json.Marshal(dm)
			bytes["dm"] = append(bytes["dm"], len(dmBytes))

			// ------------------ Anamorphic Key Generation ------------------
			t0 = time.Now()
			apk, ask, tk := AGen(64)
			t1 = time.Since(t0).Seconds()
			times["agen"] = append(times["agen"], t1)

			apkBytes, _ := json.Marshal(apk)
			askBytes, _ := json.Marshal(ask)
			tkBytes, _ := json.Marshal(tk)
			bytes["apk"] = append(bytes["apk"], len(apkBytes))
			bytes["ask"] = append(bytes["ask"], len(askBytes))
			bytes["tk"] = append(bytes["tk"], len(tkBytes))

			// ------------------ Anamorphic Encryption ------------------
			par = apk.Params
			amu := matrix.SampleMatrix(par.N, 1, par.P) // anamorphic plaintext
			t0 = time.Now()
			act := AEnc(apk, mu, amu)
			t1 = time.Since(t0).Seconds()
			times["aenc"] = append(times["aenc"], t1)

			actBytes, _ := json.Marshal(act)
			bytes["act"] = append(bytes["act"], len(actBytes))

			// ------------------ Anamorphic Decryption ------------------
			t0 = time.Now()
			adm := ADec(apk, tk, ask, act)
			t1 = time.Since(t0).Seconds()
			times["adec"] = append(times["adec"], t1)

			admBytes, _ := json.Marshal(adm)
			bytes["adm"] = append(bytes["adm"], len(admBytes))
		}
		fmt.Printf("q = 2^%d = %s\n", i, q.String())
		fmt.Println("Average times (seconds):")

		offset := len(times["kgen"]) - RUNS

		// Print average times per operation
		for key, list := range times {
			sum := 0.0
			for j := offset; j < offset+RUNS; j++ {
				sum += list[j]
			}
			avg := sum / float64(RUNS)
			fmt.Printf("  %-5s : %.6f\n", key, avg)
		}
		fmt.Println("Average sizes (bytes):")

		// Print average sizes of keys, ciphertexts, and decrypted messages
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
