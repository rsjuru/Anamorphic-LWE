package TrapdoorlessDR

import (
	"anamorphicLWE/matrix"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"time"
)

type Parameters struct {
	Q     *big.Int
	P     *big.Int
	M     int
	N     int
	Alpha float64
	Sigma float64
}

type PublicKey struct {
	Par Parameters
	B   matrix.BigIntMatrix
}

type DoubleKey struct {
	K int
	I []int
}

const Lambda = 32

// Returns k x k identity matrix mod q
func IdentityMatrix(k int, q *big.Int) matrix.BigIntMatrix {
	// Allocate outer slice for k rows
	I := make(matrix.BigIntMatrix, k)

	// Fill each row
	for i := 0; i < k; i++ {
		I[i] = make([]*big.Int, k) // allocate k columns for this row
		for j := 0; j < k; j++ {
			if i == j {
				// Diagonal element -> set to 1
				I[i][j] = big.NewInt(1)
			} else {
				// Off-diagonal element -> set to 0
				I[i][j] = big.NewInt(0)
			}
			// Reduce modulo q
			I[i][j].Mod(I[i][j], q)
		}
	}
	return I
}

// Computes (-M) mod q
func NegateMatrix(M matrix.BigIntMatrix, q *big.Int) matrix.BigIntMatrix {
	rows := len(M) // number of rows
	cols := 0
	if rows > 0 {
		cols = len(M[0]) // number of columns (assuming all rows have same length)
	}

	// Allocate result matrix
	R := make(matrix.BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		R[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Compute negation
			tmp := new(big.Int).Neg(M[i][j])

			// Reduce modulo q
			R[i][j] = new(big.Int).Mod(tmp, q)
		}
	}
	return R
}

// Checks whether every entry of M is 0 (mod q)
func AreAllZeros(M matrix.BigIntMatrix, q *big.Int) bool {
	zero := big.NewInt(0) // constant zero for comparison

	for i := range M { // iterate over rows
		for j := range M[i] {
			// Reduce entry modulo q and compare to zero
			if new(big.Int).Mod(M[i][j], q).Cmp(zero) != 0 {
				return false // found a non-zero entry
			}
		}
	}
	return true // all entries are zero mod q
}

// Generates a set of parameter for the LWE scheme
func GenParameters() Parameters {
	// Seed the pseudo-random generator with current time
	mrand.Seed(time.Now().UnixNano())

	// Plaintext modulus
	p := big.NewInt(128)

	// Ciphertext modulus
	q := new(big.Int).Lsh(big.NewInt(1), 18)

	// Sample dimensions m, n in poly(lambda)
	m := Lambda*Lambda + mrand.Intn(11)
	n := Lambda + mrand.Intn(11)

	// Sample error rate alpha
	alpha := 1.0 / (2.0 * float64(q.Int64()))
	sigma := 1.0

	// Return the parameter struct
	return Parameters{P: p, Q: q, M: m, N: n, Alpha: alpha, Sigma: sigma}
}

// Generates a secret key and corresponding public key for the LWE scheme.
func KGen() (matrix.BigIntMatrix, PublicKey) {
	// 1. Generate scheme parameters
	par := GenParameters()

	// 2. Sample a uniform random matrix A if size n x m with entries in Z_q
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// 3. Sample secret key s from P^m (entries {-1, 0, 1}) as an m x 1 matrix
	s := matrix.SampleMatrixP(par.M, 1)

	// 4. Compute s^T * A^T mod q
	AT := matrix.Transpose(A)
	sT := matrix.Transpose(s)
	As := matrix.MultiplyMatricesParallel(sT, AT, par.Q)

	// 5. Construct public key matrix B by vertically stacking A^T and As
	B := matrix.AppendRows(AT, As)

	// 6. Return secret key and public key struct
	pk := PublicKey{Par: par, B: B}
	return s, pk
}

// Generates an anamorphic LWE keypair with asymmetric anamorphic keypair (dk, tk)
func AGen() (matrix.BigIntMatrix, PublicKey, DoubleKey, matrix.BigIntMatrix) {
	// 1. Generate base LWE parameters
	par := GenParameters()

	// 2. Compute heuristic k based on m and lambda
	kFloat := math.Ceil(float64(par.M)/2.0 - math.Ceil(math.Sqrt(float64(Lambda*par.M)/2.0)))
	k := int(kFloat)

	// Ensure k is small enough for security limit
	log2q := float64(par.Q.BitLen() - 1)
	limit := float64(par.N)*log2q + 2.0*float64(Lambda)
	if float64(par.M-k) <= limit {
		k = int(math.Ceil(float64(k) / 2.0))
	}

	// 3. Sample secret s and determine zero entries J
	s := matrix.SampleMatrixP(par.M, 1)
	J := make([]int, 0)
	for i := 0; i < par.M; i++ {
		if s[i][0].Cmp(big.NewInt(0)) == 0 {
			J = append(J, i)
		}
	}

	// Retru if number of zeros < k
	maxTries := 10
	tries := 0
	for len(J) < k && tries < maxTries {
		s = matrix.SampleMatrixP(par.M, 1)
		J = J[:0]
		for i := 0; i < par.M; i++ {
			if s[i][0].Cmp(big.NewInt(0)) == 0 {
				J = append(J, i)
			}
		}
		tries++
	}
	if len(J) < k {
		return nil, PublicKey{}, DoubleKey{}, nil
	}

	// 4. Choose I ⊆ J uniformly at random, then sort for reproducibility
	mrand.Shuffle(len(J), func(a, b int) { J[a], J[b] = J[b], J[a] })
	I := make([]int, k)
	copy(I, J[:k])

	// Simple insertion sort
	for a := 1; a < len(I); a++ {
		key := I[a]
		b := a - 1
		for b >= 0 && I[b] > key {
			I[b+1] = I[b]
			b--
		}
		I[b+1] = key
	}

	// 5. Sample matrices for tk construction
	A_bar := matrix.SampleMatrix(par.M-k, par.N, par.Q)          // uniform ((m-k) x n)
	T := matrix.SampleMatrixP(par.M-k, k)                        // from P ((m-k) x k)
	TT := matrix.Transpose(T)                                    // k x (m-k)
	TT_Abar := matrix.MultiplyMatricesParallel(TT, A_bar, par.Q) // k x n
	A_prime := matrix.AppendRows(A_bar, TT_Abar)                 // stack(m x n)

	// 6. Permute rows of A_prime according to I and its complement
	fullIdx := make([]int, par.M)
	for i := 0; i < par.M; i++ {
		fullIdx[i] = i
	}
	inI := make([]bool, par.M)
	for _, idx := range I {
		inI[idx] = true
	}
	complement := make([]int, 0, par.M-k)
	for i := 0; i < par.M; i++ {
		if !inI[i] {
			complement = append(complement, i)
		}
	}
	if len(complement) != (par.M - k) {
		return nil, PublicKey{}, DoubleKey{}, nil
	}

	// 7. Initialize A (m x n) and place rows from A_prime
	A := make(matrix.BigIntMatrix, par.M)
	for i := 0; i < par.M; i++ {
		A[i] = make([]*big.Int, par.N)
		for j := 0; j < par.N; j++ {
			A[i][j] = big.NewInt(0)
		}
	}

	// place complement rows first
	for j := 0; j < (par.M - k); j++ {
		idx := complement[j]
		for col := 0; col < par.N; col++ {
			A[idx][col] = new(big.Int).Mod(new(big.Int).Set(A_prime[j][col]), par.Q)
		}
	}
	// then place rows corresponding to I
	for j := 0; j < k; j++ {
		idx := I[j]
		src := par.M - k + j
		for col := 0; col < par.N; col++ {
			A[idx][col] = new(big.Int).Mod(new(big.Int).Set(A_prime[src][col]), par.Q)
		}
	}

	// 8. Compute As = s^T * A (1 x n)
	sT := matrix.Transpose(s) //
	As := matrix.MultiplyMatricesParallel(sT, A, par.Q)

	// 9. Build public key B = [A; As]
	B := matrix.AppendRows(A, As)
	apk := PublicKey{Par: par, B: B}
	ask := s

	// 10. Build trapdoor matrix T' = [-T^T | I_k] (k x m)
	negTT := NegateMatrix(TT, par.Q)              // k x (m-k)
	Ik := IdentityMatrix(k, par.Q)                // k x k
	Tprime := matrix.HorzConcat(negTT, Ik, par.Q) // k x m

	// 11. Reorder columns of Tprime to form eT
	eT := make(matrix.BigIntMatrix, k)
	for i := 0; i < k; i++ {
		eT[i] = make([]*big.Int, par.M)
		for j := 0; j < par.M; j++ {
			eT[i][j] = big.NewInt(0)
		}
	}
	for j := 0; j < (par.M - k); j++ {
		colDst := complement[j]
		for row := 0; row < k; row++ {
			eT[row][colDst] = new(big.Int).Mod(new(big.Int).Set(Tprime[row][j]), par.Q)
		}
	}
	for j := 0; j < k; j++ {
		colDst := I[j]
		src := (par.M - k) + j
		for row := 0; row < k; row++ {
			eT[row][colDst] = new(big.Int).Mod(new(big.Int).Set(Tprime[row][src]), par.Q)
		}
	}

	// 12. Sanity checks; ensure Tprime * A_prime == 0 and eT * A == 0 (mod q)
	lhs := matrix.MultiplyMatricesParallel(Tprime, A_prime, par.Q)
	if !AreAllZeros(lhs, par.Q) {
		log.Println("Warning: Tprime * A_prime != 0 (mod q)")
	}

	te_at := matrix.MultiplyMatricesParallel(eT, A, par.Q)
	if !AreAllZeros(te_at, par.Q) {
		log.Println("Warning: eT * A != 0 (mod q)")
	}

	// 13. Pack double key information
	dk := DoubleKey{K: k, I: I}

	return ask, apk, dk, eT
}

// Encrypts a message mu using the regular public key pk.
func Enc(pk PublicKey, mu matrix.BigIntMatrix) matrix.BigIntMatrix {
	par := pk.Par
	B := pk.B

	// Compute scaling factor delta = floor(q/p)
	delta := new(big.Int).Div(par.Q, par.P)

	// 1. Sample a random uniform vector r of size n x 1
	r := matrix.SampleMatrix(par.N, 1, par.Q)

	// 2. Sample small error vectors e0 (m x 1)and e1 (1 x 1)
	e0 := matrix.SampleError(par.M, 1, par.Sigma, par.Q)
	e1 := matrix.SampleError(1, 1, par.Sigma, par.Q)

	// 3. Compute B*r mod q
	Br := matrix.MultiplyMatricesParallel(B, r, par.Q)

	// 4. Stack error vectors vertically: e = [e0; e1]
	e := matrix.AppendRows(e0, e1)

	// 5. Stack message mu with zeros (to match dimension m+1)
	zeros := make(matrix.BigIntMatrix, par.M)
	for i := 0; i < par.M; i++ {
		zeros[i] = make([]*big.Int, 1) // 1 column
		zeros[i][0] = big.NewInt(0)    // Initialize with 0
	}
	mu_stack := matrix.AppendRows(zeros, mu) // size (m+1) x 1

	// 6. Scale mu_stack by delta and reduce mod q
	delta_mustack := matrix.MultiplyMatrixByConstant(mu_stack, delta, par.Q)

	// 7. Compute ciphertext: c = B*r + e + delta*mu_stack (mod q)
	tmp := matrix.AddMatrices(Br, e, par.Q)
	c := matrix.AddMatrices(tmp, delta_mustack, par.Q)

	return c
}

// Performs anamorphic LWE encryption
func AEnc(apk PublicKey, dk DoubleKey, mu *big.Int, muHat matrix.BigIntMatrix) [][]*big.Int {
	par, B := apk.Par, apk.B

	// Compute delta = ceil(q/p)
	delta := new(big.Int).Div(par.Q, par.P)
	if new(big.Int).Mod(par.Q, par.P).Cmp(big.NewInt(0)) != 0 {
		delta = new(big.Int).Add(delta, big.NewInt(1)) // ceil
	}

	// 1. Sample randomness r, e0, e1
	r := matrix.SampleMatrix(par.N, 1, par.Q)            // n x 1
	e0 := matrix.SampleError(par.M, 1, par.Sigma, par.Q) // m x 1
	e1 := matrix.SampleError(1, 1, par.Sigma, par.Q)     // 1 x 1

	// 2. Construct f vector (m x 1), embedding muHat at indices I
	f := make(matrix.BigIntMatrix, par.M)
	for i := 0; i < par.M; i++ {
		f[i] = []*big.Int{big.NewInt(0)}
	}
	for j, idx := range dk.I {
		f[idx][0] = new(big.Int).Set(muHat[j][0])
	}

	// 3. Compute Br = B * r mod q
	Br := matrix.MultiplyMatricesParallel(B, r, par.Q)

	// 4. Stack e = [e0; e1]
	e := matrix.AppendRows(e0, e1)

	// 5. Stack f and mu vertically: f_and_mu = [f; mu]
	muCol := matrix.BigIntMatrix{{mu}}
	fAndMu := matrix.AppendRows(f, muCol)

	// 6. Multiply by delta mod q
	deltaTerm := matrix.MultiplyMatrixByConstant(fAndMu, delta, par.Q)

	// 7. Compute ciphertext: c = Br + e + deltaTerm mod q
	c := matrix.AddMatrices(Br, e, par.Q)
	c = matrix.AddMatrices(c, deltaTerm, par.Q)

	return c
}

// Decrypts a ciphertext using the secret key sk.
func Dec(par Parameters, sk, ct matrix.BigIntMatrix) *big.Int {
	// 1. Compute delta = q / p
	delta := new(big.Int).Div(par.Q, par.P)

	// 2. Construct sk_neg = [-sk^T | 1]
	skT := matrix.Transpose(sk)
	sk_neg := make(matrix.BigIntMatrix, len(skT)) // will be 1 x (m+1)
	for i := range skT {
		sk_neg[i] = make([]*big.Int, len(skT[i])+1)
		for j := range skT[i] {
			// Negate each entry modulo q
			tmp := new(big.Int).Neg(skT[i][j])
			sk_neg[i][j] = tmp.Mod(tmp, par.Q)
		}
		// Append the last entry as 1
		sk_neg[i][len(skT[i])] = big.NewInt(1)
	}

	// 3. Compute nu = sk_neg * ct (1 x 1) mod q
	nu := matrix.MultiplyMatricesParallel(sk_neg, ct, par.Q)
	nuVal := new(big.Int).Set(nu[0][0])

	// 4. Recover plaintext: round nu / delta to nearest integer, then mod p
	qdiv := matrix.RoundDiv(nuVal, delta)
	mu := new(big.Int).Mod(qdiv, par.P)

	return mu
}

// Performs anamorphic decryption of a ciphertext.
// It recovers anamorphic message mu_hat from the anamorphic ciphertext act.s
func ADec(par Parameters, dk DoubleKey, tk, act matrix.BigIntMatrix) matrix.BigIntMatrix {
	// 1. Compute delta = ceil(q / p)
	delta := new(big.Int).Div(par.Q, par.P)
	if new(big.Int).Mod(par.Q, par.P).Cmp(big.NewInt(0)) != 0 {
		delta = new(big.Int).Add(delta, big.NewInt(1)) // ceiling
	}

	// 2. Build extended matrix [tk | 0] (k x (m+1))
	TeExt := make(matrix.BigIntMatrix, dk.K)
	for i := 0; i < dk.K; i++ {
		TeExt[i] = append(tk[i], big.NewInt(0)) // append zero col
	}

	// 3. Compute nu_hat = TeExt * act mod q
	nu_hat := matrix.MultiplyMatricesParallel(TeExt, act, par.Q)

	// 4. Recover mu_hat
	muHat := make(matrix.BigIntMatrix, len(nu_hat))
	for i := 0; i < len(nu_hat); i++ {
		muHat[i] = make([]*big.Int, len(nu_hat[0]))
		for j := 0; j < len(nu_hat[0]); j++ {
			// Round nu_hat / delta to nearest integer
			rounded := matrix.RoundDiv(nu_hat[i][j], delta)
			// Reduce mod p to get original message space
			muHat[i][j] = new(big.Int).Mod(rounded, par.P)
		}
	}
	return muHat
}
