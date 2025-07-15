package main

import (
	"fmt"
	"time"

	"gonum.org/v1/gonum/mat"
)

func RunLWEBenchmark() {
	const REPEATS = 100
	q := 1 << 16 // 2^16

	// Initialize timing data
	times := map[string][]float64{
		"key_gen":     {},
		"a_key_gen":   {},
		"regular_enc": {},
		"regular_dec": {},
		"a_enc":       {},
		"a_dec":       {},
	}

	for i := 0; i < REPEATS; i++ {
		// Key generation
		t0 := time.Now()
		sk, pk := kgen(2, q)
		t1 := time.Since(t0).Seconds() * 1000
		times["key_gen"] = append(times["key_gen"], t1)

		t0 = time.Now()
		_, apk, dk, tk := agen(2, q)
		t1 = time.Since(t0).Seconds() * 1000
		times["a_key_gen"] = append(times["a_key_gen"], t1)

		// Common inputs
		par := pk.Params
		p, _, _, l, _ := par.p, par.n, par.m, par.l, par.alpha
		mu := randomVec(l, p)
		smu := randomVec(l, p)

		// Regular encryption
		t0 = time.Now()
		c0, c1 := enc(pk, mu, p, q)
		t1 = time.Since(t0).Seconds() * 1000
		times["regular_enc"] = append(times["regular_enc"], t1)

		// Regular decryption
		t0 = time.Now()
		decMu := dec(sk, [2]*mat.Dense{c0, c1}, p, q)
		_ = decMu
		t1 = time.Since(t0).Seconds() * 1000
		times["regular_dec"] = append(times["regular_dec"], t1)

		// Anamorphic encryption
		t0 = time.Now()
		act := aenc(apk, dk, mu, smu)
		t1 = time.Since(t0).Seconds() * 1000
		times["a_enc"] = append(times["a_enc"], t1)

		// Anamorphic decryption
		t0 = time.Now()
		sMuRec, _ := adec(tk, dk, act, pk, 2)
		_ = sMuRec
		t1 = time.Since(t0).Seconds() * 1000
		times["a_dec"] = append(times["a_dec"], t1)
	}

	fmt.Println("\nBenchmark Summary (times in milliseconds):")
	fmt.Println("============================================")
	fmt.Printf("%-35s %10s\n", "Operation", "Avg Time (ms)")
	fmt.Println("============================================")

	for name, values := range times {
		fmt.Printf("%-35s %10.3f\n", nameToTitle(name), average(values))
	}
	fmt.Println("============================================")
}

func average(xs []float64) float64 {
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func nameToTitle(key string) string {
	names := map[string]string{
		"key_gen":     "Key Generation",
		"a_key_gen":   "Anamorphic Key Generation",
		"regular_enc": "Regular LWE Encryption",
		"regular_dec": "Regular LWE Decryption",
		"a_enc":       "Anamorphic Encryption",
		"a_dec":       "Anamorphic Decryption",
	}
	return names[key]
}
