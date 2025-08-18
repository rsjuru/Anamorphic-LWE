// Save this as lwe.go and run with: go run lwe.go

package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

type BigIntMatrix [][]*big.Int

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

const lam = 2

// Matrix Addition: result = (a + b) mod mod
func addMatrices(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])
	result := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			sum := new(big.Int).Add(a[i][j], b[i][j])
			result[i][j] = sum.Mod(sum, mod)
		}
	}
	return result
}

// Matrix Subtraction: result = (a - b) mod mod
func subtractMatrices(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])
	result := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			diff := new(big.Int).Sub(a[i][j], b[i][j])
			result[i][j] = diff.Mod(diff, mod)
		}
	}
	return result
}

// Matrix-Constant Multiplication: result = (a * constant) mod mod
func multiplyMatrixByConstant(a BigIntMatrix, constant, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])
	result := make(BigIntMatrix, rows)
	tmp := new(big.Int)
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			tmp.Mul(a[i][j], constant)
			result[i][j] = new(big.Int).Mod(tmp, mod)
		}
	}
	return result
}

func multiplyMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(b[0])
	inner := len(b)

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

// Sample a random matrix with entries in Z_mod
func sampleMatrix(rows, cols int, mod *big.Int) BigIntMatrix {
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int).Rand(rng, mod)
		}
	}
	return result
}

// Sample error matrix using normal distribution
func sampleError(rows, cols int, stddev float64, mod *big.Int) BigIntMatrix {
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			x := rng.NormFloat64() * stddev
			result[i][j] = big.NewInt(int64(math.Round(x)))
		}
	}
	return result
}

// Transpose a matrix
func Transpose(matrix BigIntMatrix) BigIntMatrix {
	rows, cols := len(matrix), len(matrix[0])
	result := make(BigIntMatrix, cols)
	for i := range result {
		result[i] = make([]*big.Int, rows)
	}
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j][i] = new(big.Int).Set(matrix[i][j])
		}
	}
	return result
}

// Compute ceil(log2(x))
func log2BigInt(x *big.Int) int {
	return x.BitLen()
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
	q     *big.Int
	p     *big.Int
	n     int
	m     int
	l     int
	alpha float64
}

type PublicKey struct {
	Params ParameterSet
	A      BigIntMatrix
	U      BigIntMatrix
}

func genParameters(qOpt ...*big.Int) ParameterSet {
	q := new(big.Int).SetUint64(1 << 15)
	if len(qOpt) > 0 {
		q = qOpt[0]
	}
	p := big.NewInt(5)
	k := log2BigInt(q)
	l := 4 * lam
	n := 2*l*k + 2*lam
	m := (n+l)*k + 2*lam
	return ParameterSet{q: q, p: p, n: n, m: m, l: l, alpha: 0.5}
}

// Key Generation
func kgen(q *big.Int) (PublicKey, BigIntMatrix) {
	par := genParameters(q)
	A := sampleMatrix(par.n, par.m, par.q)
	S := sampleMatrix(par.n, par.l, par.q)
	E := sampleError(par.l, par.m, par.alpha, par.q)
	AT := Transpose(A)
	ATS := multiplyMatricesParallel(AT, S, par.q)
	ET := Transpose(E)
	U := Transpose(addMatrices(ATS, ET, par.q))
	return PublicKey{Params: par, A: A, U: U}, S
}

// Encryption
func enc(pk PublicKey, mu BigIntMatrix) [2]BigIntMatrix {
	par := pk.Params
	r := sampleMatrix(par.m, 1, big.NewInt(2))

	qF := new(big.Float).SetInt(par.q)
	pF := new(big.Float).SetInt(par.p)
	delta := new(big.Float).Quo(qF, pF)
	deltaInt := new(big.Int)
	delta.Int(deltaInt)

	mu_q := multiplyMatrixByConstant(mu, deltaInt, par.q)
	c0 := multiplyMatricesParallel(pk.A, r, par.q)
	c1 := addMatrices(multiplyMatricesParallel(pk.U, r, par.q), mu_q, par.q)
	return [2]BigIntMatrix{c0, c1}
}

// Decryption
func dec(par ParameterSet, sk BigIntMatrix, ct [2]BigIntMatrix) BigIntMatrix {
	qF := new(big.Float).SetInt(par.q)
	pF := new(big.Float).SetInt(par.p)
	delta := new(big.Float).Quo(qF, pF)
	halfDelta := new(big.Float).Quo(delta, big.NewFloat(2))

	ST := Transpose(sk)
	c0s := multiplyMatricesParallel(ST, ct[0], par.q)
	diff := subtractMatrices(ct[1], c0s, par.q)

	rows, cols := len(diff), len(diff[0])
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			tmp := new(big.Float).SetInt(diff[i][j])
			tmp.Add(tmp, halfDelta)
			tmp.Quo(tmp, delta)
			rounded := new(big.Int)
			tmp.Int(rounded)
			result[i][j] = rounded.Mod(rounded, par.p)
		}
	}
	return result
}

func agen(q *big.Int) (PublicKey, BigIntMatrix, [2]BigIntMatrix, BigIntMatrix) {
	par := genParameters(q)
	k := log2BigInt(par.q)

	G := gadgetMatrixParallel(par.l, k, par.q)

	bar_m := par.l*k + 2*lam

	barC := sampleMatrix(par.l, bar_m, par.q)
	R := sampleError(bar_m, par.l*k, 0.5, par.q)

	barC_R := multiplyMatricesParallel(barC, R, par.q)
	right := addMatrices(barC_R, G, par.q)

	C := hstack(barC, right)

	B := sampleError(par.l, par.m, 0.5, par.q)
	F := sampleError(par.m, par.n, 0.5, par.q)

	CT := Transpose(C)
	CB := multiplyMatricesParallel(CT, B, par.q)
	FT := Transpose(F)
	A := addMatrices(CB, FT, par.q)

	S := sampleMatrix(par.n, par.l, par.q)
	E := sampleError(par.l, par.m, 0.5, par.q)

	AT := Transpose(A)
	ATS := multiplyMatricesParallel(AT, S, par.q)
	ET := Transpose(E)
	U := Transpose(addMatrices(ATS, ET, par.q))

	D := multiplyMatricesParallel(C, S, par.q)

	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, S, [2]BigIntMatrix{C, D}, R
}

func aenc(apk PublicKey, dk [2]BigIntMatrix, mu, smu BigIntMatrix) [2]BigIntMatrix {
	par := apk.Params
	A := apk.A
	U := apk.U
	C := dk[0]
	D := dk[1]

	qFloat := new(big.Float).SetInt(par.q)
	pFloat := new(big.Float).SetInt(par.p)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	r := sampleMatrix(par.m, 1, new(big.Int).SetInt64(2))

	mu_q := multiplyMatrixByConstant(mu, deltaRounded, par.q)
	s := multiplyMatrixByConstant(smu, deltaRounded, par.q)

	Ar := multiplyMatricesParallel(A, r, par.q)
	CT := Transpose(C)
	CTs := multiplyMatricesParallel(CT, s, par.q)
	c0 := addMatrices(Ar, CTs, par.q)

	Ur := multiplyMatricesParallel(U, r, par.q)
	DT := Transpose(D)
	DTs := multiplyMatricesParallel(DT, s, par.q)
	sum := addMatrices(Ur, DTs, par.q)
	c1 := addMatrices(sum, mu_q, par.q)

	return [2]BigIntMatrix{c0, c1}
}

func adec(tk BigIntMatrix, act [2]BigIntMatrix, apk PublicKey) BigIntMatrix {
	c0 := act[0]
	par := apk.Params
	k := log2BigInt(par.q)

	splitIndex := par.l*k + 2*lam

	c0_part1 := sliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := sliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	RT := Transpose(tk)
	tmp := multiplyMatricesParallel(RT, c0_part1, par.q)
	c0_diff := subtractMatrices(c0_part2, tmp, par.q)

	S := calculateSMatrixParallel(k, par.l, par.q)
	ST := Transpose(S)
	diff_T := multiplyMatricesParallel(ST, c0_diff, par.q)
	Gs := subtractMatrices(c0_diff, diff_T, par.q)
	s := recoverKthColumn(Gs, k, par.l)
	sFinal := ScaleAndRoundMatrix(s, par.p, par.q)

	return sFinal
}

// Check equality
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
	q := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
	pk, sk := kgen(q)
	par := pk.Params
	mu := sampleMatrix(par.l, 1, par.p)

	fmt.Println("Original message:", Transpose(mu))

	ct := enc(pk, mu)
	dm := dec(par, sk, ct)

	fmt.Println("Decrypted message:", Transpose(dm))

	if matEqual(mu, dm) {
		fmt.Println("LWE decryption works! ✅")
	} else {
		fmt.Println("LWE decryption fails! ❌")
	}

	amu := sampleMatrix(par.l, 1, par.p)
	apk, ask, dk, tk := agen(q)
	par = apk.Params
	ct = enc(apk, mu)
	dm = dec(par, ask, ct)
	fmt.Println("Original Message: ", Transpose(mu))
	fmt.Println("Decrypted message: ", Transpose(dm))

	if matEqual(mu, dm) {
		fmt.Println("LWE decryption works with anamorphic key pair! ✅")
	} else {
		fmt.Println("LWE decryption fails with anamorphic key pair! ❌")
	}

	act := aenc(apk, dk, mu, amu)
	adm := adec(tk, act, apk)

	fmt.Println("Original anamorphic message: ", Transpose(amu))
	fmt.Println("Decrypted anamorphic message: ", Transpose(adm))

	if matEqual(amu, adm) {
		fmt.Println("Anamorphic decryption works! ✅")
	} else {
		fmt.Println("Anamorphic decryption fails! ❌")
	}

	dm = dec(par, ask, act)

	fmt.Println("Original message: ", Transpose(mu))
	fmt.Println("Original message decrypted from anamorphic ciphertext: ", Transpose(dm))

	if matEqual(mu, dm) {
		fmt.Println("Regular decryption works with anamorphic ciphertext! ✅")
	} else {
		fmt.Println("Regular decryption fails with anamorphic ciphertext! ❌")
	}

}
func main() {
	// functionality()
	runTests()
}
