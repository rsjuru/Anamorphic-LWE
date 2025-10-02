package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"runtime"
	"sync"
	"time"
)

type BigIntMatrix [][]*big.Int

type Parameters struct {
	q     *big.Int
	p     *big.Int
	m     int
	n     int
	alpha float64
	sigma float64
}

type PublicKey struct {
	par Parameters
	B   BigIntMatrix
}

var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

const lambda = 64

// Generates a random matrix of size (rows x cols)
// with entries uniformly sampled from Z_q (integers modulo q).
func sampleMatrix(rows, cols int, q *big.Int) BigIntMatrix {
	matrix := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Sample uniformly at random in [0, q-1]
			matrix[i][j] = new(big.Int).Rand(rng, q)
		}
	}
	return matrix
}

// Generates a matrix of size (rows x cols) where each entry
// is sampled from a discrete Gaussian (normal) distribution
// with mean 0 and given standard deviation (stddev).
func sampleError(rows, cols int, stddev float64, mod *big.Int) BigIntMatrix {
	matrix := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Draw a sample from N(0, stddev^2)
			x := rng.NormFloat64() * stddev

			// Round to nearest integer
			intVal := int64(math.Round(x))

			// Store as big.Int
			matrix[i][j] = new(big.Int).SetInt64(intVal)
		}
	}
	return matrix
}

// SampleMatrixP generates an m × n matrix where each entry is from P = {-1:1/4, 0:1/2, +1:1/4}
func SampleMatrixP(m, n int) BigIntMatrix {
	matrix := make([][]*big.Int, m)
	for i := 0; i < m; i++ {
		row := make([]*big.Int, n)
		for j := 0; j < n; j++ {
			// Sample from {0, 1, 2, 3} and map to {-1, 0, 1}
			randVal, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				log.Fatalf("crand.Int error: %v", err)
			}
			switch randVal.Int64() {
			case 0, 1:
				row[j] = big.NewInt(0)
			case 2:
				row[j] = big.NewInt(-1)
			case 3:
				row[j] = big.NewInt(1)
			}
		}
		matrix[i] = row
	}
	return matrix
}

// Multiplies two matrices (a * b) with entries in Z_mod.
// using parallelism to speed up computation.
func multiplyMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)     // number of rows in 'a'
	cols := len(b[0])  // number of columns in 'b'
	inner := len(a[0]) // shared inner dimensions (a.cols == b.rows)

	// Allocate result matrix (rows x cols), initialized with zeros
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int) // each entry starts as 0
		}
	}

	// Determine number of workers = number of CPU cores
	numWorkers := runtime.NumCPU()
	runtime.GOMAXPROCS(numWorkers)

	// Split the work into batches of rows per worker
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

			tmp := new(big.Int) // temporary for multplication
			sum := new(big.Int) // accumulator for each cell

			// Multiply the corresponding row (from 'a') and column (from 'b')
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					sum.SetInt64(0) // reset accumulator
					for k := 0; k < inner; k++ {
						tmp.Mul(a[i][k], b[k][j]) // a[i][j] * b[k][j]
						sum.Add(sum, tmp)         // accumulate
					}
					result[i][j].Mod(sum, mod) // reduce modulo 'mod'
				}
			}
		}(start, end)
	}

	wg.Wait() // wait for all goroutines to finish
	return result
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

// Multiplies every entry of matrix 'a' by 'constant'
// and reduces the result modulo 'mod'
func multiplyMatrixByConstant(a BigIntMatrix, constant, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])

	// Allocate result matrix with same dimensions
	result := make(BigIntMatrix, rows)

	// Temporary variable to hold intermediate products
	tmp := new(big.Int)
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Multiply entry by the constant
			tmp.Mul(a[i][j], constant)

			// Reduce modulo 'mod' and store in result
			result[i][j] = new(big.Int).Mod(tmp, mod)
		}
	}
	return result
}

// Adds two matrices 'a' and 'b' element-wise modulo mod
func addMatrices(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])

	// Allocate result matrix
	result := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Add entries a[i][j] + b[i][j]
			sum := new(big.Int).Add(a[i][j], b[i][j])

			// Reduce modulo 'mod' and store in result
			result[i][j] = sum.Mod(sum, mod)
		}
	}
	return result
}

// appendRows stacks two matrices vertically:
// A: r1 x c, B: r2 x c → result: (r1+r2) x c
func appendRows(A, B BigIntMatrix) BigIntMatrix {
	if len(A) == 0 {
		return B
	}
	if len(B) == 0 {
		return A
	}
	colsA := len(A[0])
	colsB := len(B[0])
	if colsA != colsB {
		panic(fmt.Sprintf("appendRows: mismatched column sizes (%d vs %d)", colsA, colsB))
	}

	rows := len(A) + len(B)
	cols := colsA
	result := make(BigIntMatrix, rows)
	for i := 0; i < len(A); i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			result[i][j] = new(big.Int).Set(A[i][j])
		}
	}
	for i := 0; i < len(B); i++ {
		result[len(A)+i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			result[len(A)+i][j] = new(big.Int).Set(B[i][j])
		}
	}
	return result
}

// RoundDiv returns ⌊a/b⌉ (round to nearest integer).
func RoundDiv(a, b *big.Int) *big.Int {
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(a, b, r) // q = a/b (truncated), r = remainder

	// If remainder >= b/2, round up
	half := new(big.Int).Div(b, big.NewInt(2))
	if r.Cmp(half) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

func genParameters() Parameters {
	mrand.Seed(time.Now().UnixNano())
	p := big.NewInt(128)
	q := new(big.Int).Lsh(big.NewInt(1), 18)

	// Sample dimensions m, n in poly(lambda)
	m := lambda*lambda + mrand.Intn(11)
	n := lambda + mrand.Intn(11)

	// Sample error rate alpha
	alpha := 1.0 / (2.0 * float64(q.Int64()))
	sigma := 1.0

	return Parameters{p: p, q: q, m: m, n: n, alpha: alpha, sigma: sigma}
}

func kGen() (BigIntMatrix, PublicKey) {
	par := genParameters()

	// Sample matrix A from (n x m)
	A := sampleMatrix(par.n, par.m, par.q)
	s := SampleMatrixP(par.m, 1)

	// Compute s^T * A^T mod q
	AT := Transpose(A)
	sT := Transpose(s)
	As := multiplyMatricesParallel(sT, AT, par.q)

	// Public key: vertically stack A^T and As
	B := appendRows(AT, As)

	pk := PublicKey{par: par, B: B}
	return s, pk
}

func enc(pk PublicKey, mu BigIntMatrix) BigIntMatrix {
	par := pk.par
	B := pk.B
	delta := new(big.Int).Div(par.q, par.p)

	// Sample uniform vector r
	r := sampleMatrix(par.n, 1, par.q)

	// Sample error vectors e0 and e1
	e0 := sampleError(par.m, 1, par.sigma, par.q)
	e1 := sampleError(1, 1, par.sigma, par.q)

	// Compute B*r
	Br := multiplyMatricesParallel(B, r, par.q)

	// Vertically stack e0 and e1
	e := appendRows(e0, e1)

	// Vertically stack 0^m and mu
	zeros := make(BigIntMatrix, par.m)
	for i := 0; i < par.m; i++ {
		zeros[i] = make([]*big.Int, 1) // 1 column
		zeros[i][0] = big.NewInt(0)    // Initialize with 0
	}
	mu_stack := appendRows(zeros, mu)
	delta_mustack := multiplyMatrixByConstant(mu_stack, delta, par.q)

	// Compute c = Br + e + delta*mu_stack
	tmp := addMatrices(Br, e, par.q)
	c := addMatrices(tmp, delta_mustack, par.q)

	return c
}

func dec(par Parameters, sk, ct BigIntMatrix) *big.Int {
	delta := new(big.Int).Div(par.q, par.p)

	// Construct sk_neg = [-sk^T | 1]
	skT := Transpose(sk)
	sk_neg := make(BigIntMatrix, len(skT))
	for i := range skT {
		sk_neg[i] = make([]*big.Int, len(skT[i])+1)
		for j := range skT[i] {
			tmp := new(big.Int).Neg(skT[i][j])
			sk_neg[i][j] = tmp.Mod(tmp, par.q)
		}
		sk_neg[i][len(skT[i])] = big.NewInt(1)
	}

	// Compute nu = [-sk | 1] * ct
	nu := multiplyMatricesParallel(sk_neg, ct, par.q)
	nuVal := new(big.Int).Set(nu[0][0])
	qdiv := RoundDiv(nuVal, delta)
	mu := new(big.Int).Mod(qdiv, par.p)

	return mu
}

func main() {
	iterations := 1000
	regularSuccess := 0

	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration round:", i+1)
		sk, pk := kGen()
		par := pk.par
		mu := sampleMatrix(1, 1, par.p)
		ct := enc(pk, mu)
		dm := dec(par, sk, ct)

		if mu[0][0].String() == dm.String() {
			regularSuccess++
		}
	}

	fmt.Println(regularSuccess, "/", iterations, "regular decryptions succeeded!")

}
