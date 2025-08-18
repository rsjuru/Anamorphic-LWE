package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"time"
)

type BigIntMatrix [][]*big.Int

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

var lam = 2

func addMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(a[0])
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int)
		}
	}

	numWorkers := 8
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			sum := new(big.Int)
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					sum.Add(a[i][j], b[i][j])
					result[i][j].Mod(sum, mod)
				}
			}
		}(start, end)
	}

	wg.Wait()
	return result
}

func multiplyMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(b[0])
	inner := len(a[0]) // or len(b)

	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int)
		}
	}

	numWorkers := runtime.NumCPU()
	runtime.GOMAXPROCS(numWorkers)
	batchSize := (rows + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			tmp := new(big.Int)
			sum := new(big.Int)

			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					sum.SetInt64(0)
					for k := 0; k < inner; k++ {
						tmp.Mul(a[i][k], b[k][j])
						sum.Add(sum, tmp)
					}
					result[i][j].Mod(sum, mod)
				}
			}
		}(start, end)
	}

	wg.Wait()
	return result
}

func subtractMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(a[0])
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int)
		}
	}

	numWorkers := 8
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			diff := new(big.Int)
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					diff.Sub(a[i][j], b[i][j])
					// Ensure positive mod
					result[i][j].Mod(diff, mod)
					if result[i][j].Sign() < 0 {
						result[i][j].Add(result[i][j], mod)
					}
				}
			}
		}(start, end)
	}

	wg.Wait()
	return result
}

func multiplyMatrixByConstantParallel(matrix BigIntMatrix, constant, mod *big.Int) BigIntMatrix {
	rows := len(matrix)
	cols := len(matrix[0])
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int)
		}
	}

	numWorkers := 8
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			tmp := new(big.Int)
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					tmp.Mul(matrix[i][j], constant)
					result[i][j].Mod(tmp, mod)
				}
			}
		}(start, end)
	}

	wg.Wait()
	return result
}

func ScaleAndRoundMatrix(a BigIntMatrix, p, q *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(a[0])
	result := make(BigIntMatrix, rows)

	pf := new(big.Float).SetInt(p)
	qf := new(big.Float).SetInt(q)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			val := new(big.Float).SetInt(a[i][j])
			scaled := new(big.Float).Quo(new(big.Float).Mul(val, pf), qf)
			rounded := new(big.Float).Add(scaled, big.NewFloat(0.5))
			intVal := new(big.Int)
			rounded.Int(intVal)
			intVal.Mod(intVal, p)
			if intVal.Sign() < 0 {
				intVal.Add(intVal, p)
			}
			result[i][j] = intVal
		}
	}
	return result
}

func sampleMatrix(rows, cols int, q *big.Int) BigIntMatrix {
	matrix := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			matrix[i][j] = new(big.Int).Rand(rng, q)
		}
	}
	return matrix
}

func sampleError(rows, cols int, stddev float64, mod *big.Int) BigIntMatrix {
	matrix := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			x := rng.NormFloat64() * stddev
			intVal := int64(math.Round(x))
			matrix[i][j] = new(big.Int).SetInt64(intVal)
		}
	}
	return matrix
}

func Transpose(matrix BigIntMatrix) BigIntMatrix {
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil
	}

	rows := len(matrix)
	cols := len(matrix[0])

	// Create transposed matrix
	transposed := make(BigIntMatrix, cols)
	for i := range transposed {
		transposed[i] = make([]*big.Int, rows)
	}

	// Fill transposed matrix
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			transposed[j][i] = new(big.Int).Set(matrix[i][j])
		}
	}

	return transposed
}

// log2BigInt returns the ceiling of log₂(x) for big.Int x.
func log2BigInt(x *big.Int) int {
	bitLen := x.BitLen()
	// Check if x is a power of 2
	if new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLen-1)), nil).Cmp(x) == 0 {
		return bitLen - 1
	}
	return bitLen
}

func gadgetMatrixParallel(n, k int, q *big.Int) BigIntMatrix {
	// Step 1: Create gadget vector g = [1, 2, 4, ..., 2^{k-1}] mod q
	g := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		val := new(big.Int).Lsh(big.NewInt(1), uint(i)) // 1 << i
		val.Mod(val, q)
		g[i] = val
	}

	// Step 2: Initialize G = n x (n * k) matrix
	rows := n
	cols := n * k
	G := make(BigIntMatrix, rows)
	for i := range G {
		G[i] = make([]*big.Int, cols)
		for j := range G[i] {
			G[i][j] = big.NewInt(0)
		}
	}

	// Step 3: Parallel Kronecker product G = I_n ⊗ g
	numWorkers := 8
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				base := i * k
				for j := 0; j < k; j++ {
					G[i][base+j] = new(big.Int).Set(g[j])
				}
			}
		}(start, end)
	}

	wg.Wait()
	return G
}

func calculateSMatrixParallel(k, n int, q *big.Int) BigIntMatrix {
	// Step 1: Create qBits vector of k least significant bits of q
	qBits := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		bit := q.Bit(i)
		qBits[i] = big.NewInt(int64(bit))
	}

	// Step 2: Construct Sk matrix (k x k)
	Sk := make(BigIntMatrix, k)
	for i := 0; i < k; i++ {
		Sk[i] = make([]*big.Int, k)
		for j := 0; j < k; j++ {
			Sk[i][j] = big.NewInt(0)
		}
	}
	for i := 0; i < k; i++ {
		if i > 0 {
			Sk[i][i-1] = big.NewInt(-1)
		}
		if i < k-1 {
			Sk[i][i] = big.NewInt(2)
		}
		Sk[i][k-1] = new(big.Int).Set(qBits[i])
	}

	// Step 3: Initialize output S of size (n*k) x (n*k)
	rows := n * k
	cols := n * k
	S := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		S[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			S[i][j] = big.NewInt(0)
		}
	}

	// Step 4: Parallelize the Kronecker product
	numWorkers := 8
	type task struct{ i, j int }

	tasks := make(chan task, n*n)
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				if t.i == t.j { // since I is identity
					for r := 0; r < k; r++ {
						for c := 0; c < k; c++ {
							val := new(big.Int).Set(Sk[r][c]) // copy Sk element
							S[t.i*k+r][t.j*k+c] = val
						}
					}
				}
			}
		}()
	}

	// Enqueue tasks
	for i := 0; i < n; i++ {
		tasks <- task{i, i} // Only the diagonal (since I is identity)
	}
	close(tasks)
	wg.Wait()

	return S
}

func hstack(left, right BigIntMatrix) BigIntMatrix {
	// Get dimensions of the left matrix
	r1 := len(left)
	c1 := 0
	if r1 > 0 {
		c1 = len(left[0])
	}

	// Get dimensions of the right matrix
	r2 := len(right)
	c2 := 0
	if r2 > 0 {
		c2 = len(right[0])
	}

	// Ensure both matrices have the same number of rows
	if r1 != r2 {
		panic("hstack: row dimensions do not match")
	}

	// Allocate result matrix with r1 rows and (c1 + c2) columns
	result := make(BigIntMatrix, r1)
	for i := 0; i < r1; i++ {
		result[i] = make([]*big.Int, c1+c2)
		// Coput left matrix row
		for j := 0; j < c1; j++ {
			result[i][j] = new(big.Int).Set(left[i][j])
		}
		// Copy right matrix row
		for j := 0; j < c2; j++ {
			result[i][c1+j] = new(big.Int).Set(right[i][j])
		}
	}
	return result
}

func sliceBigIntMatrixColRange(matrix BigIntMatrix, rowStart, rowEnd, colStart, colEnd int) BigIntMatrix {
	if rowStart < 0 || rowEnd > len(matrix) || rowStart > rowEnd {
		panic("invalid row range")
	}
	if len(matrix) == 0 || colStart < 0 || colEnd > len(matrix[0]) || colStart > colEnd {
		panic("invalid column range")
	}

	sliced := make(BigIntMatrix, rowEnd-rowStart)
	for i := rowStart; i < rowEnd; i++ {
		row := make([]*big.Int, colEnd-colStart)
		for j := colStart; j < colEnd; j++ {
			row[j-colStart] = new(big.Int).Set(matrix[i][j]) // deep copy
		}
		sliced[i-rowStart] = row
	}
	return sliced
}

func recoverKthColumn(Gs BigIntMatrix, k int, n int) BigIntMatrix {
	s := make(BigIntMatrix, n)
	for i := 0; i < n; i++ {
		s[i] = []*big.Int{new(big.Int).Set(Gs[i*k][0])} // deep copy
	}
	return s
}

type ParameterSet struct {
	q      *big.Int
	p      *big.Int
	n      int
	mBar   int
	alpha  float64
	stdDev float64
}

type PublicKey struct {
	Params ParameterSet
	A      BigIntMatrix
	U      BigIntMatrix
}

func gen_parameters(qOpt ...*big.Int) ParameterSet {
	q := new(big.Int).SetUint64(1 << 15)
	if len(qOpt) > 0 {
		q = qOpt[0]
	}

	p := new(big.Int).SetUint64(5)

	// High-precision log2(q)
	qFloat := new(big.Float).SetInt(q)
	log2q := new(big.Float).Quo(new(big.Float).SetPrec(256).SetFloat64(math.Log2E), new(big.Float).SetFloat64(math.Log(2)))
	log2q.Mul(log2q, new(big.Float).SetPrec(256).SetInt(q))

	k := log2BigInt(q)

	n := lam
	mBar := n*k + 2*lam

	// alpha = 1 / (2q)
	alpha := new(big.Float).Quo(big.NewFloat(1.0), new(big.Float).Mul(big.NewFloat(2.0), qFloat))
	stdDev := 1.0
	new_alpha, _ := alpha.Float64()

	return ParameterSet{
		q:      q,
		p:      p,
		n:      n,
		mBar:   mBar,
		alpha:  new_alpha,
		stdDev: stdDev,
	}
}

func kgen(q *big.Int) (BigIntMatrix, PublicKey) {
	// Generate parameter set
	par := gen_parameters(q)

	k := log2BigInt(q)
	m := par.mBar + par.n*k

	// Sample matrix A
	A := sampleMatrix(par.n, m, q)

	// Sample error matrix E
	E := sampleError(m, par.n, par.stdDev, q)

	// Compute U = A*E
	U := multiplyMatricesParallel(A, E, q)

	return E, PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}
}

func enc(pk PublicKey, mu BigIntMatrix) [2]BigIntMatrix {
	par := pk.Params
	A := pk.A
	U := pk.U

	qFloat := new(big.Float).SetInt(par.q)
	pFloat := new(big.Float).SetInt(par.p)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding
	// deltaHalf := new(big.Float).Quo(delta, big.NewFloat(2))

	// Sample s, e0, e1
	s := sampleMatrix(par.n, 1, par.q)
	k := log2BigInt(par.q)
	m := par.mBar + par.n*k
	e0 := sampleError(m, 1, par.stdDev, par.q)
	e1 := sampleError(par.n, 1, par.stdDev, par.q)

	// delta * mu
	mu_q := multiplyMatrixByConstantParallel(mu, deltaRounded, par.q)

	AT := Transpose(A)
	As := multiplyMatricesParallel(AT, s, par.q)
	c0 := addMatricesParallel(As, e0, par.q)

	UT := Transpose(U)
	Us := multiplyMatricesParallel(UT, s, par.q)
	Us_e := addMatricesParallel(Us, e1, par.q)
	c1 := addMatricesParallel(Us_e, mu_q, par.q)

	return [2]BigIntMatrix{c0, c1}
}

func dec(par ParameterSet, sk BigIntMatrix, ct [2]BigIntMatrix) BigIntMatrix {
	c0, c1 := ct[0], ct[1]

	qFloat := new(big.Float).SetInt(par.q)
	pFloat := new(big.Float).SetInt(par.p)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaHalf := new(big.Float).Quo(delta, big.NewFloat(2))
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded)

	ST := Transpose(sk)
	c0_s := multiplyMatricesParallel(ST, c0, par.q)
	diff := subtractMatricesParallel(c1, c0_s, par.q)

	rows := len(diff)
	cols := len(diff[0])
	result := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Convert to big.Float
			tmp := new(big.Float).SetInt(diff[i][j])
			tmp.Add(tmp, deltaHalf)
			tmp.Quo(tmp, delta)

			rounded := new(big.Int)
			tmp.Int(rounded)
			rounded.Mod(rounded, par.p)
			result[i][j] = rounded
		}
	}
	return result
}

func agen(q *big.Int) (apk PublicKey, ask BigIntMatrix, tk BigIntMatrix) {
	// Generate parameters (same as kgen)
	par := gen_parameters(q)
	k := log2BigInt(q)
	m := par.mBar + par.n*k

	// Generate trapdoor matrix R ∈ {−1, 0, 1}
	R := sampleError(par.mBar, par.n*k, par.stdDev, q)
	A_bar := sampleMatrix(par.n, par.mBar, q)
	G := gadgetMatrixParallel(par.n, k, q)

	// right side of A = A_bar*R + G
	AR := multiplyMatricesParallel(A_bar, R, q)
	right := addMatricesParallel(AR, G, q)
	A := hstack(A_bar, right)
	E := sampleError(m, par.n, par.stdDev, q)

	U := multiplyMatricesParallel(A, E, q)

	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, E, R
}

func aenc(apk PublicKey, mu, mu_bar BigIntMatrix) [2]BigIntMatrix {
	par := apk.Params
	A := apk.A
	U := apk.U
	k := log2BigInt(par.q)
	m := par.mBar + par.n*k

	// Sample vectors s, e0 and e1
	s := sampleError(par.n, 1, 0.5, par.q)
	e0 := sampleError(m, 1, par.stdDev, par.q)
	e1 := sampleError(par.n, 1, par.stdDev, par.q)

	// Compute delta = round(q / p)
	qFloat := new(big.Float).SetInt(par.q)
	pFloat := new(big.Float).SetInt(par.p)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	mu_q := multiplyMatrixByConstantParallel(mu, deltaRounded, par.q)
	mu_bar_q := multiplyMatrixByConstantParallel(mu_bar, deltaRounded, par.q)

	s_hat := addMatricesParallel(s, mu_bar_q, par.q)
	AT := Transpose(A)
	As := multiplyMatricesParallel(AT, s_hat, par.q)
	c0 := addMatricesParallel(As, e0, par.q)

	// Compute c1 = U^T*s_hat + e1 + mu_q
	UT := Transpose(U)
	Us := multiplyMatricesParallel(UT, s_hat, par.q)
	Us_e := addMatricesParallel(Us, e1, par.q)
	c1 := addMatricesParallel(Us_e, mu_q, par.q)

	return [2]BigIntMatrix{c0, c1}
}

func adec(apk PublicKey, tk, ask BigIntMatrix, act [2]BigIntMatrix) BigIntMatrix {
	c0 := act[0]
	par := apk.Params
	k := log2BigInt(par.q)

	splitIndex := par.mBar

	c0_part1 := sliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := sliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	RT := Transpose(tk)
	tmp := multiplyMatricesParallel(RT, c0_part1, par.q)
	c0_diff := subtractMatricesParallel(c0_part2, tmp, par.q)

	// G := gadgetMatrix(par.n, k, par.q)
	S := calculateSMatrixParallel(k, par.n, par.q)

	ST := Transpose(S)
	diff_T := multiplyMatricesParallel(ST, c0_diff, par.q)
	Gs := subtractMatricesParallel(c0_diff, diff_T, par.q)
	s := recoverKthColumn(Gs, k, par.n)
	sFinal := ScaleAndRoundMatrix(s, par.p, par.q)

	return sFinal
}

func matEqual(a, b BigIntMatrix) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j].Cmp(b[i][j]) != 0 {
				return false
			}
		}

	}
	return true
}

func functionality() {
	q := new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)
	sk, pk := kgen(q)
	par := pk.Params
	mu := sampleMatrix(par.n, 1, par.p)
	fmt.Printf("Original message: %v\n", Transpose(mu))

	ct := enc(pk, mu)
	dm := dec(par, sk, ct)
	fmt.Printf("Decrypted message: %v\n", Transpose(dm))

	if matEqual(mu, dm) {
		fmt.Println("LWE Decryption works! ✅")
	} else {
		fmt.Println("LWE decryptions fails! ❌")
	}

	apk, ask, tk := agen(q)
	par = apk.Params
	mu = sampleMatrix(par.n, 1, par.p)
	amu := sampleMatrix(par.n, 1, par.p)

	fmt.Printf("Regular message: %v\n", Transpose(mu))
	fmt.Printf("Anamorphic message: %v\n", Transpose(amu))

	ct = enc(apk, mu)
	dm = dec(par, ask, ct)

	fmt.Printf("Original message: %v\n", Transpose(mu))
	fmt.Printf("Decrypted message: %v\n", Transpose(mu))

	if matEqual(mu, dm) {
		fmt.Println("Dual Regev works with anamorphic key pair! ✅")
	} else {
		fmt.Println("Dual Regev fails with anamorphic key pair! ❌")
	}

	act := aenc(apk, mu, amu)
	adm := adec(apk, tk, ask, act)

	fmt.Printf("Original anamorphic message: %v\n", Transpose(amu))
	fmt.Printf("Decrypted anamorphic message: %v\n", Transpose(adm))

	if matEqual(amu, adm) {
		fmt.Println("Anamorphic Dual Regev decryption works! ✅")
	} else {
		fmt.Println("Anamorphic Dual Regev decryption fails! ❌")
	}

	dm = dec(par, ask, act)

	fmt.Printf("Original message in anamorphic ciphertext: %v\n", Transpose(mu))
	fmt.Printf("Decrypted original message from anamorphic ciphertext: %v\n", Transpose(dm))

	if matEqual(mu, dm) {
		fmt.Println("Regular decryption works on anamorphic ciphertext! ✅")
	} else {
		fmt.Println("Regular decryption fails on anamorphic ciphertext! ❌")
	}
}

func main() {
	// functionality()
	// runTests()
	testLambda()
}
