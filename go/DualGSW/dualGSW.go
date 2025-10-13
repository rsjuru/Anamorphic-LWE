package DualGSW

import (
	"anamorphicLWE/matrix"
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
	N0    int
	Alpha float64
	Sigma float64
	L     int
}

type PublicKey struct {
	Par Parameters
	B   matrix.BigIntMatrix
}

type AKeySet struct {
	Ask matrix.BigIntMatrix
	Apk PublicKey
	Dk  []int
	Tk  matrix.BigIntMatrix
}

const L = 3

// Extracts the first column of a matrix and returns it as a vector
func flattenMatrix(mat matrix.BigIntMatrix) []*big.Int {
	n := len(mat) // number of rows in the matrix

	// Allocate a slice to hold the first column
	res := make([]*big.Int, n)

	// Copy each element from the first column of each row
	for i := 0; i < n; i++ {
		// Copy the value from the first column of each row
		res[i] = new(big.Int).Set(mat[i][0])
	}
	return res
}

// Generates the cryptographic parameters for a scheme
// based on a modulus q.
func genParameters(lam int) Parameters {
	// Seed the math/rand pseudo-random generator
	mrand.Seed(time.Now().UnixNano())

	// Define key dimensions and plaintext modulus
	n := lam
	p := big.NewInt(256) // plaintext modulus
	q := new(big.Int).Lsh(big.NewInt(1), 18)
	k := int(math.Ceil(math.Log2(float64(q.Int64()))))
	m := 5 * n

	// Randomize n0 within safe bounds
	upperLimit := int(math.Floor(float64(m)/2.0 - math.Ceil(math.Sqrt(float64(lam*m)/2.0))))
	if upperLimit < 2 {
		upperLimit = 2
	}
	n0 := mrand.Intn(upperLimit-1) + 2

	// Ensure that m is sufficiently large for the system to be solvable
	if m-n0 <= n*k+2*lam {
		m = n*k + 2*lam + n0 + 1
	}

	// Define noise parameters
	alpha := 1.0 / (2.0 * float64(q.Int64())) // relative error bound
	sigma := 1.0                              // standard deviation for Gaussian noise

	return Parameters{
		Q:     q,
		P:     p,
		M:     m,
		N:     n,
		N0:    n0,
		Alpha: alpha,
		Sigma: sigma,
		L:     L,
	}
}

// Generates a secret key and a correspoinding public key
// for a lattice-based scheme.
func KGen(lam int) (sk matrix.BigIntMatrix, pk PublicKey) {
	// Generate cryptographic parameters
	par := genParameters(lam)

	// Sample uniform matrix A (n x m)
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// Sample secret vector s (m x 1) from P = {-1, 0, 1}
	s := matrix.SampleMatrixP(par.M, 1)

	// Compute s^T * A^T mod q
	A_T := matrix.Transpose(A)
	s_T := matrix.Transpose(s)
	As := matrix.MultiplyMatricesParallel(s_T, A_T, par.Q)

	// Public key: vertically stack A^T and As
	rowsA := len(A_T)
	rowsAs := len(As)
	cols := len(A_T[0])

	B := make(matrix.BigIntMatrix, rowsA+rowsAs)

	// Copy A^T into the top rows of B
	for i := 0; i < rowsA; i++ {
		B[i] = make([]*big.Int, cols)
		copy(B[i], A_T[i])
	}

	// Copy As into the bottom row(s) of B
	for i := 0; i < rowsAs; i++ {
		B[rowsA+i] = make([]*big.Int, cols)
		copy(B[rowsA+i], As[i])
	}

	// Assign public and secret key
	pk.Par = par
	pk.B = B
	sk = s

	return
}

// Generates key set for anamorphic dual GSW scheme.
func AGen(lam int) *AKeySet {
	// Generate cryptographic parameters and secret vector s
	par := genParameters(lam)
	s := matrix.SampleMatrixP(par.M, 1)

	// Identify zero positions in s (needed for trapdoor construction)
	J := []int{}
	for i := 0; i < par.M; i++ {
		if s[i][0].Cmp(big.NewInt(0)) == 0 {
			J = append(J, i)
		}
	}

	// if not enough zeros for trapdoor, return failure
	if len(J) < par.N0 {
		return nil
	}

	// Randomly select n0 indices from J
	mrand.Shuffle(len(J), func(i, j int) { J[i], J[j] = J[j], J[i] })
	I := J[:par.N0]

	// Construct intermediate matrix A_hat (size n x n0)
	// A0: n x (n0-1)
	A0 := matrix.SampleMatrix(par.N, par.N0-1, par.Q)
	tPrime := matrix.SampleError(par.N0-1, 1, 0.5, par.Q)
	eI := matrix.SampleError(par.N, 1, 0.5, par.Q)

	// A_hat = [A0.T; tPrime^T*A0^T + eI^T] mod q
	A0T := matrix.Transpose(A0)
	tPrimeT := matrix.Transpose(tPrime)
	eIT := matrix.Transpose(eI)
	AOtPrime := matrix.MultiplyMatricesParallel(tPrimeT, A0T, par.Q)
	sum := matrix.AddMatrices(AOtPrime, eIT, par.Q)
	A_hat := matrix.AppendRows(A0T, sum)
	A_hatT := matrix.Transpose(A_hat) // transpose for column assignement

	// Initialize random matrix A: n x m
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// Assign selected columns from A_hat into A
	for j := 0; j < par.N0; j++ {
		for row := 0; row < par.N; row++ {
			A[row][I[j]] = A_hatT[row][j] // insert A_hat columns at indices I
		}
	}

	// Construct trapdoor vector t (m x 1)
	t := make(matrix.BigIntMatrix, par.M)
	for i := 0; i < par.M; i++ {
		t[i] = make([]*big.Int, 1)
		t[i][0] = big.NewInt(0) // initialize to 0
	}

	for j := 0; j < par.N0-1; j++ {
		idx := I[j]
		neg := new(big.Int).Neg(tPrime[j][0]) // negative tPrime
		t[idx][0] = neg
	}
	// last trapdoor index set to 1
	t[I[par.N0-1]][0] = big.NewInt(1)

	// build public matrix B
	AT := matrix.Transpose(A)
	sT := matrix.Transpose(s)
	As := matrix.MultiplyMatricesParallel(sT, AT, par.Q)
	B := matrix.AppendRows(AT, As)

	// Construct public key struct
	apk := PublicKey{Par: par, B: B}

	return &AKeySet{Ask: s, Apk: apk, Dk: I, Tk: t}
}

// Encrypts a plaintext message mu using the public key pk.
func Enc(pk PublicKey, mu *big.Int) matrix.BigIntMatrix {
	par := pk.Par

	// Compute the gadget dimension parameter k
	k := int(math.Ceil(math.Log2(float64(par.Q.Int64()))))
	M := k * (par.M + 1) // width of the random masking matrix

	// Sample random masking matrix S (n x M)
	S := matrix.SampleMatrix(par.N, M, par.Q)

	// Sample small error matrix E ((m+1) x M)
	E := matrix.SampleError(par.M+1, M, par.Sigma, par.Q)

	// Compute BS = B * S mod q
	BS := matrix.MultiplyMatricesParallel(pk.B, S, par.Q)

	// Gadget matrix G od size (m+1) x (m+1)*k
	G := matrix.GadgetMatrixParallel(par.M+1, k, par.Q)

	Gmu := matrix.MultiplyMatrixByConstant(G, mu, par.Q)

	// Sum = (BS + Gmu) mod q
	sum := matrix.AddMatrices(BS, Gmu, par.Q)

	// Add noise: C = (sum + E) mod q
	C := matrix.AddMatrices(sum, E, par.Q)

	return C
}

// Performs anamorphic encryption with a trapdoor-aware public key.
func AEnc(apk PublicKey, dk []int, mu, muHat *big.Int) matrix.BigIntMatrix {
	par := apk.Par

	// Compute gadget dimensions k and M
	logQ := math.Log2(float64(par.Q.Int64()))
	k := int(math.Ceil(logQ))
	M := k * (par.M + 1)

	// Sample random matrices for masking and noise
	S := matrix.SampleError(par.N, M, 0.5, par.Q)         // masking matrix
	E := matrix.SampleError(par.M+1, M, par.Sigma, par.Q) // small error matrix

	// Construct diagonal matrix J with muHat at trapdoor indices
	J := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		J[i] = make([]*big.Int, par.M+1)
		for j := 0; j < par.M+1; j++ {
			J[i][j] = big.NewInt(0)
			if i == j { // only diagonal entries
				found := false
				for _, idx := range dk {
					if idx == j {
						J[i][j] = new(big.Int).Set(muHat) // use covert plaintext at trapdoor
						found = true
						break
					}
				}
				if !found {
					J[i][j] = new(big.Int).Set(mu) // standard plaintext elsewhere
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
	Jg := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		Jg[i] = make([]*big.Int, M)
		for col := 0; col < M; col++ {
			Jg[i][col] = big.NewInt(0) // initialize all entries
		}
		for j := 0; j < par.M+1; j++ {
			if J[i][j].Cmp(big.NewInt(0)) != 0 {
				for t := 0; t < k; t++ {
					colIdx := j*k + t
					Jg[i][colIdx].Mul(J[i][j], g[t])
					Jg[i][colIdx].Mod(Jg[i][colIdx], par.Q)
				}
			}
		}
	}

	// C = (B*S + Jg + E) mod q
	BS := matrix.MultiplyMatricesParallel(apk.B, S, par.Q)
	tmp := matrix.AddMatrices(BS, Jg, par.Q)
	C := matrix.AddMatrices(tmp, E, par.Q)

	return C
}

// Decrypts a ciphertext matrix using the secret key sk.
func Dec(par Parameters, sk matrix.BigIntMatrix, ct matrix.BigIntMatrix) *big.Int {

	// Compute scaling factor delta = round(q / p)
	delta := new(big.Int).Div(par.Q, par.P)

	// Construct embedding vector em = [0,...,0,1]^T
	em := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M; i++ {
		em[i] = []*big.Int{big.NewInt(0)}
	}
	em[par.M] = []*big.Int{big.NewInt(1)}

	// Multiply by delta for scaling: emDelta = delta * em
	emDelta := matrix.MultiplyMatrixByConstant(em, delta, par.Q)

	// Construct sk_neg = [-sk^T | 1]
	sk_T := matrix.Transpose(sk)
	sk_neg := make(matrix.BigIntMatrix, len(sk_T))
	for i := range sk_T {
		sk_neg[i] = make([]*big.Int, len(sk_T[i])+1)
		for j := range sk_T[i] {
			tmp := new(big.Int).Neg(sk_T[i][j]) // negate secret
			sk_neg[i][j] = tmp.Mod(tmp, par.Q)  // modulo q
		}
		sk_neg[i][len(sk_T[i])] = big.NewInt(1) // append 1
	}

	// Compute Cs = sk_neg * ct mod q
	Cs := matrix.MultiplyMatricesParallel(sk_neg, ct, par.Q)

	// Gadget decomposition of em_delta
	G_neg := matrix.GadgetInverse(flattenMatrix(emDelta), par.Q, 2)

	// nu = Cs * G_neg mod q
	nu := matrix.MultiplyMatricesParallel(Cs, G_neg, par.Q)

	// Recover plaintext: mu = round(nu / delta) mod p
	nuVal := new(big.Int).Set(nu[0][0])
	qdiv := matrix.RoundDiv(nuVal, delta)
	mu := new(big.Int).Mod(qdiv, par.P)

	return mu
}

// Performs trapdoor-assisted decryption using anamorphic decryption.
func ADec(par Parameters, dk []int, tk, ask, act matrix.BigIntMatrix) *big.Int {
	// Compute scaling factor delta = round(q / p)
	delta := new(big.Int).Div(par.Q, par.P)

	// Construct embedding vector eHat ((m+1) x 1)
	// Only the last trapdoor index is set to 1
	eHat := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		eHat[i] = make([]*big.Int, 1)
		eHat[i][0] = big.NewInt(0)
	}
	eHat[dk[len(dk)-1]][0] = big.NewInt(1)

	// Scale by delta: deltae = delta * eHat
	deltae := matrix.MultiplyMatrixByConstant(eHat, delta, par.Q)

	// Gadget inverse for deltae
	G_inv := matrix.GadgetInverse(flattenMatrix(deltae), par.Q, 2)

	// Construct tRow = [tk^T | 0] (1 x (m+1))
	tRow := make(matrix.BigIntMatrix, 1)
	tRow[0] = make([]*big.Int, par.M+1)
	for i := 0; i < par.M; i++ {
		tRow[0][i] = new(big.Int).Set(tk[i][0])
	}
	tRow[0][par.M] = big.NewInt(0)

	// Multiply tRow by ciphertext matrix act mod q
	rowC := matrix.MultiplyMatricesParallel(tRow, act, par.Q)

	// Multiply rowC by gadget inverse to get nu
	nu := matrix.MultiplyMatricesParallel(rowC, G_inv, par.Q)

	// Recover plaintext muHat = round(nu / delta) mod p
	nu_scalar := nu[0][0]
	qdiv := matrix.RoundDiv(nu_scalar, delta)
	mutHat := new(big.Int).Mod(qdiv, par.P)

	return mutHat
}
