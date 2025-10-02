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
	q      *big.Int
	p      *big.Int
	m      int
	n      int
	n0     int
	alpha  float64
	stddev float64
	L      int
}

type PublicKey struct {
	par Parameters
	B   BigIntMatrix
}

type AKeySet struct {
	ask BigIntMatrix
	apk PublicKey
	dk  []int
	tk  BigIntMatrix
}

var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

const lambda = 2
const L = 3

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

// Constructs the gadget matrix G in parallel
func gadgetMatrixParallel(n, k int, q *big.Int) BigIntMatrix {
	// Build the base gadget vector g = (1, 2, 4, ..., 2*(k-1))
	g := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		val := new(big.Int).Lsh(big.NewInt(1), uint(i))
		val.Mod(val, q)
		g[i] = val
	}

	// Initialize empty matrix G with dimensions n x (n*k)
	rows := n
	cols := n * k
	G := make(BigIntMatrix, rows)
	for i := range G {
		G[i] = make([]*big.Int, cols)
		for j := range G[i] {
			G[i][j] = big.NewInt(0)
		}
	}

	// Parallelization settings
	numWorkers := 8 // fixed number of goroutines
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	// Split rows into chunks and assign to workers
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
				base := i * k // start index for row i
				for j := 0; j < k; j++ {
					// Place g[j] in the correct block position
					G[i][base+j] = new(big.Int).Set(g[j])
				}
			}
		}(start, end)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	return G
}

func gadgetInverse(vec []*big.Int, q *big.Int, base int64) BigIntMatrix {

	// Compute k = ceil(log_base(q))
	// using float (if q is small enough to convert safely)
	qf, _ := new(big.Float).SetInt(q).Float64()
	k := int(math.Ceil(math.Log(qf) / math.Log(float64(base))))

	digits := make([]*big.Int, 0, len(vec)*k)

	baseBig := big.NewInt(base)

	for _, x := range vec {
		y := new(big.Int).Set(x)
		for i := 0; i < k; i++ {
			digit := new(big.Int).Mod(y, baseBig)
			digits = append(digits, digit)
			y.Div(y, baseBig)
		}
	}

	res := make(BigIntMatrix, len(digits))
	for i := range digits {
		res[i] = []*big.Int{digits[i]}
	}

	return res
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

// Extracts the first column of a matrix and returns it as a vector
func flattenMatrix(mat BigIntMatrix) []*big.Int {
	n := len(mat) // number of rows
	res := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		// Copy the value from the first column of each row
		res[i] = new(big.Int).Set(mat[i][0])
	}
	return res
}

func genParameters(q *big.Int) Parameters {
	mrand.Seed(time.Now().UnixNano())

	n := lambda * 2
	p := big.NewInt(256) // plaintext modulus
	k := int(math.Ceil(math.Log2(float64(q.Int64()))))
	m := 10 * n

	upperLimit := int(math.Floor(float64(m)/2.0 - math.Ceil(math.Sqrt(float64(lambda*m)/2.0))))
	if upperLimit < 2 {
		upperLimit = 2
	}

	n0 := mrand.Intn(upperLimit-1) + 2
	if m-n0 <= n*k+2*lambda {
		m = n*k + 2*lambda + n0 + 1
	}

	alpha := 1.0 / (2.0 * float64(q.Int64()))
	sigma := 1.0

	return Parameters{
		q:      q,
		p:      p,
		m:      m,
		n:      n,
		n0:     n0,
		alpha:  alpha,
		stddev: sigma,
		L:      L,
	}

}

func kGen(q *big.Int) (sk BigIntMatrix, pk PublicKey) {
	par := genParameters(q)

	// Sample uniform matrix A (n x m)
	A := sampleMatrix(par.n, par.m, par.q)

	// Sample secret vector s (m x 1) from P = {-1, 0, 1}
	s := SampleMatrixP(par.m, 1)

	// Compute s^T * A^T mod q
	A_T := Transpose(A)
	s_T := Transpose(s)
	As := multiplyMatricesParallel(s_T, A_T, q)

	// Public key: vertically stack A^T and As
	rowsA := len(A_T)
	rowsAs := len(As)
	cols := len(A_T[0])

	B := make(BigIntMatrix, rowsA+rowsAs)
	for i := 0; i < rowsA; i++ {
		B[i] = make([]*big.Int, cols)
		copy(B[i], A_T[i])
	}
	for i := 0; i < rowsAs; i++ {
		B[rowsA+i] = make([]*big.Int, cols)
		copy(B[rowsA+i], As[i])
	}

	pk.par = par
	pk.B = B
	sk = s

	return
}

func aGen(q *big.Int) *AKeySet {
	// Generate parameters
	par := genParameters(q)

	s := SampleMatrixP(par.m, 1)

	// Find zero positions in s
	J := []int{}
	for i := 0; i < par.m; i++ {
		if s[i][0].Cmp(big.NewInt(0)) == 0 {
			J = append(J, i)
		}
	}

	// if not enough zeros for trapdoor, return failure
	if len(J) < par.n0 {
		return nil
	}

	// Randomly select n0 indices from J
	mrand.Shuffle(len(J), func(i, j int) { J[i], J[j] = J[j], J[i] })
	I := J[:par.n0]

	// Construct A_har (size n x n0)
	// A0: n x (n0-1)
	A0 := sampleMatrix(par.n, par.n0-1, par.q)
	tPrime := sampleError(par.n0-1, 1, 0.5, par.q)
	eI := sampleError(par.n, 1, 0.5, par.q)

	// A_hat = [A0.T; tPrime^T*A0^T + eI^T] mod q
	A0T := Transpose(A0)
	tPrimeT := Transpose(tPrime)
	eIT := Transpose(eI)
	// fmt.Println("Size of A0:", len(A0), "x", len(A0[0]))
	// fmt.Println("Size of tPrimeT:", len(tPrimeT), "x", len(tPrimeT[0]))
	AOtPrime := multiplyMatricesParallel(tPrimeT, A0T, par.q)
	sum := addMatrices(AOtPrime, eIT, par.q)
	A_hat := appendRows(A0T, sum)
	A_hatT := Transpose(A_hat)

	// Random A: n x m
	A := sampleMatrix(par.n, par.m, par.q)

	// Assign selected columns from A_hat into A
	for j := 0; j < par.n0; j++ {
		for row := 0; row < par.n; row++ {
			A[row][I[j]] = A_hatT[row][j]
		}
	}

	// Construct trapdoor vector t (m x 1)
	t := make(BigIntMatrix, par.m)
	for i := 0; i < par.m; i++ {
		t[i] = make([]*big.Int, 1)
		t[i][0] = big.NewInt(0)
	}

	for j := 0; j < par.n0-1; j++ {
		idx := I[j]
		neg := new(big.Int).Neg(tPrime[j][0])
		t[idx][0] = neg
	}
	// last trapdoor index
	t[I[par.n0-1]][0] = big.NewInt(1)

	// build public matrix B
	AT := Transpose(A)
	sT := Transpose(s)
	As := multiplyMatricesParallel(sT, AT, par.q)

	B := appendRows(AT, As)
	apk := PublicKey{par: par, B: B}

	return &AKeySet{ask: s, apk: apk, dk: I, tk: t}
}

func enc(pk PublicKey, mu *big.Int) BigIntMatrix {
	par := pk.par
	k := int(math.Ceil(math.Log2(float64(par.q.Int64()))))
	M := k * (par.m + 1)

	// Sample random masking matrix S (n x M)
	S := sampleMatrix(par.n, M, par.q)

	// Sample small error matrix E ((m+1) x M)
	E := sampleError(par.m+1, M, par.stddev, par.q)

	// Compute BS = B * S mod q
	BS := multiplyMatricesParallel(pk.B, S, par.q)

	// Gadget matrix G od size (m+1) x (m+1)*k
	G := gadgetMatrixParallel(par.m+1, k, par.q)

	Gmu := multiplyMatrixByConstant(G, mu, par.q)

	// Sum = (BS + Gmu) mod q
	sum := addMatrices(BS, Gmu, par.q)

	// Add noise: C = (sum + E) mod q
	C := addMatrices(sum, E, par.q)

	return C
}

func aenc(apk PublicKey, dk []int, mu, muHat *big.Int) BigIntMatrix {
	par := apk.par

	logQ := math.Log2(float64(par.q.Int64()))
	k := int(math.Ceil(logQ))
	M := k * (par.m + 1)

	// S = error matrix (n x M), E = error matrix ((m + 1), M)
	// stddevAlpha := par.alpha * float64(par.q.Int64())
	S := sampleError(par.n, M, 0.5, par.q)
	E := sampleError(par.m+1, M, par.stddev, par.q)

	// Build diagonal matrix J with muHat at indices in dk, else mu
	J := make(BigIntMatrix, par.m+1)
	for i := 0; i < par.m+1; i++ {
		J[i] = make([]*big.Int, par.m+1)
		for j := 0; j < par.m+1; j++ {
			J[i][j] = big.NewInt(0)
			if i == j {
				found := false
				for _, idx := range dk {
					if idx == j {
						J[i][j] = new(big.Int).Set(muHat)
						found = true
						break
					}
				}
				if !found {
					J[i][j] = new(big.Int).Set(mu)
				}
			}
		}
	}

	//g = [1, 2, 4, ..., 2^(k-1)]
	g := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		g[i] = new(big.Int).Lsh(big.NewInt(1), uint(i))
	}

	// Compute Jg = kron(J, g) (size (m+1) x M)
	Jg := make(BigIntMatrix, par.m+1)
	for i := 0; i < par.m+1; i++ {
		Jg[i] = make([]*big.Int, M)
		for col := 0; col < M; col++ {
			Jg[i][col] = big.NewInt(0) // <- no nils
		}
		for j := 0; j < par.m+1; j++ {
			if J[i][j].Cmp(big.NewInt(0)) != 0 {
				for t := 0; t < k; t++ {
					colIdx := j*k + t
					Jg[i][colIdx].Mul(J[i][j], g[t])
					Jg[i][colIdx].Mod(Jg[i][colIdx], par.q)
				}
			}
		}
	}

	// fmt.Println("Size of B:", len(apk.B), "x", len(apk.B[0]))
	// fmt.Println("Size of S:", len(S), "x", len(S[0]))
	// C = (B*S + Jg + E) mod q
	BS := multiplyMatricesParallel(apk.B, S, par.q)
	tmp := addMatrices(BS, Jg, par.q)
	C := addMatrices(tmp, E, par.q)

	return C
}

func dec(par Parameters, sk BigIntMatrix, ct BigIntMatrix) *big.Int {

	// delta = round(q/p)
	delta := new(big.Int).Div(par.q, par.p)

	// Construct embedding vector em of size (m+1) x 1 with last entry = 1
	em := make(BigIntMatrix, par.m+1)
	for i := 0; i < par.m; i++ {
		em[i] = []*big.Int{big.NewInt(0)}
	}
	em[par.m] = []*big.Int{big.NewInt(1)}

	// em_delta = delta * em
	emDelta := multiplyMatrixByConstant(em, delta, par.q)

	// Construct sk_neg = [-sk^T | 1]
	sk_T := Transpose(sk)
	sk_neg := make(BigIntMatrix, len(sk_T))
	for i := range sk_T {
		sk_neg[i] = make([]*big.Int, len(sk_T[i])+1)
		for j := range sk_T[i] {
			tmp := new(big.Int).Neg(sk_T[i][j])
			sk_neg[i][j] = tmp.Mod(tmp, par.q)
		}
		sk_neg[i][len(sk_T[i])] = big.NewInt(1)
	}

	// Compute Cs = sk_neg * ct mod q
	Cs := multiplyMatricesParallel(sk_neg, ct, par.q)

	// Gadget decomposition of em_delta
	G_neg := gadgetInverse(flattenMatrix(emDelta), par.q, 2)

	// fmt.Println("Cs:", len(Cs), "x", len(Cs[0]))
	// fmt.Println("G_neg:", len(G_neg), "x", len(G_neg[0]))

	// nu = Cs * G_neg mod q
	nu := multiplyMatricesParallel(Cs, G_neg, par.q)

	// Recover plaintext: mu = round(nu / delta) mod p
	nuVal := new(big.Int).Set(nu[0][0])
	qdiv := RoundDiv(nuVal, delta)
	mu := new(big.Int).Mod(qdiv, par.p)

	return mu
}

func adec(par Parameters, dk []int, tk, ask, act BigIntMatrix) *big.Int {
	// Compute delta = round(q/p)
	delta := new(big.Int).Div(par.q, par.p)

	// Construct e_hat vector ((m+1) x 1)
	eHat := make(BigIntMatrix, par.m+1)
	for i := 0; i < par.m+1; i++ {
		eHat[i] = make([]*big.Int, 1)
		eHat[i][0] = big.NewInt(0)
	}
	// Set embedding unit vector
	eHat[dk[len(dk)-1]][0] = big.NewInt(1)

	// delta * e_hat
	deltae := multiplyMatrixByConstant(eHat, delta, par.q)

	// Gadget inverse
	G_inv := gadgetInverse(flattenMatrix(deltae), par.q, 2)

	// Concatenate tk row with 0 to form t_row
	tRow := make(BigIntMatrix, 1)
	tRow[0] = make([]*big.Int, par.m+1)
	for i := 0; i < par.m; i++ {
		tRow[0][i] = new(big.Int).Set(tk[i][0])
	}
	tRow[0][par.m] = big.NewInt(0)

	// Multiply t_row * act mod q
	rowC := multiplyMatricesParallel(tRow, act, par.q)

	// Multiply rowC * Ginv mod q
	nu := multiplyMatricesParallel(rowC, G_inv, par.q)

	// Convert 1x1 result to scalar
	nu_scalar := nu[0][0]
	qdiv := RoundDiv(nu_scalar, delta)
	mutHat := new(big.Int).Mod(qdiv, par.p)

	return mutHat
}

func main() {
	// ------------------ Initialization ------------------

	// Set modulus q = 2^15
	q := new(big.Int).Lsh(big.NewInt(1), 15)

	// Generate standard secret/public key pair
	sk, pk := kGen(q)

	// Generate anamorphic key set (for anamorphic encryption)
	aks := aGen(q)
	apk := aks.apk // Extract public key from anamorphic key set

	// Counters to track succesfull decryptions
	regularSuccess := 0
	anamorphicSuccess := 0

	iterations := 1000 // Number of messages

	// ------------------ Encryption/Decryption Loop ------------------

	for i := 0; i < iterations; i++ {
		fmt.Println("Iteration number:", i+1)

		// 1. Regular message encryption/decryption
		mu, _ := rand.Int(rand.Reader, pk.par.p) // Sample random plaintext mu ∈ Zp
		ct := enc(pk, mu)                        // Encrypt using standard scheme
		dm := dec(pk.par, sk, ct)                // Decrypt ciphertext

		// Check if decryption was correct
		if mu.String() == dm.String() {
			regularSuccess++
		} else {
			fmt.Println("Regular message: ", mu, "and decrypted one: ", dm)
		}

		// 2. Anamorphic message encryption/decryption
		muHat, _ := rand.Int(rand.Reader, apk.par.p) // Sample random plaintext for anamorphic encryption

		act := aenc(apk, aks.dk, mu, muHat)                // Encrypt message using anamorphic scheme
		adm := adec(apk.par, aks.dk, aks.tk, aks.ask, act) // Decrypt ciphertext

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
